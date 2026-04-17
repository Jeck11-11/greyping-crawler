"""FastAPI application – OSINT Reconnaissance API."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

import httpx

from ._http_utils import fetch_landing_page, fetch_landing_page_full, normalise_target
from .breach_checker import check_breaches
from .cookie_checker import analyze_cookies
from .crawler import crawl_domain
from .fair_signals import compute_fair_signals
from .js_miner import mine_javascript
from .extractors import extract_contacts, extract_links, extract_page_metadata
from .ioc_scanner import scan_ioc
from .models import (
    ContactInfo,
    CTResult,
    DNSResult,
    DomainResult,
    DomainSummary,
    EmailSecurityResult,
    EmailFinding,
    ExternalLinkFinding,
    IPEnrichmentResult,
    JSIntelResult,
    LinkInfo,
    PageResult,
    PassiveIntelResult,
    PhoneFinding,
    RDAPResult,
    ReconRequest,
    ScanRequest,
    ScanResponse,
    ScanSummary,
    SecurityHeadersResult,
    SocialFinding,
    SSLCertResult,
    WaybackResult,
)
from .passive_intel import (
    query_ct_logs,
    query_dns,
    query_email_security,
    query_ip_enrichment,
    query_rdap,
    query_wayback,
)
from .path_scanner import scan_sensitive_paths
from .routers import content as content_router
from .routers import discovery as discovery_router
from .routers import intel as intel_router
from .routers import network as network_router
from .routers import passive as passive_router
from .secret_scanner import scan_secrets
from .security_headers import analyze_headers
from .ssl_checker import check_ssl
from .tech_fingerprint import fingerprint_tech

logger = logging.getLogger("osint_api")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="GreyPing OSINT Reconnaissance API",
    description=(
        "Real-time website scanning and data extraction API. "
        "Crawls domains to extract contacts, links, exposed secrets, "
        "and checks against breach databases."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(network_router.router)
app.include_router(content_router.router)
app.include_router(discovery_router.router)
app.include_router(intel_router.router)
app.include_router(passive_router.router)


_SOCIAL_PLATFORM_MAP = {
    "twitter.com": "Twitter", "x.com": "Twitter/X",
    "facebook.com": "Facebook", "fb.com": "Facebook",
    "linkedin.com": "LinkedIn", "instagram.com": "Instagram",
    "github.com": "GitHub", "youtube.com": "YouTube",
    "tiktok.com": "TikTok", "pinterest.com": "Pinterest",
    "reddit.com": "Reddit", "t.me": "Telegram",
    "mastodon.social": "Mastodon",
}


def _detect_platform(url: str) -> str:
    """Return the platform name for a social URL, or empty string."""
    try:
        host = (urlparse(url).hostname or "").lower().lstrip("www.")
        return _SOCIAL_PLATFORM_MAP.get(host, "")
    except Exception:
        return ""


def _extract_domain(url: str) -> str:
    """Return the bare domain from a URL."""
    parsed = urlparse(url)
    return (parsed.hostname or url).lower().lstrip("www.")


# Backwards-compatible aliases — existing callers / tests may import these.
_normalise_target = normalise_target
_fetch_landing_page = fetch_landing_page


async def _scan_single_target(
    target: str,
    request: ScanRequest,
) -> DomainResult:
    """Run the full scan pipeline for a single target domain."""
    domain = _extract_domain(target)
    started = datetime.now(timezone.utc).isoformat()

    # Run crawl, SSL check, landing-page fetch (for headers/cookies/HTML),
    # and sensitive-path scan concurrently.
    crawl_task = crawl_domain(
        target,
        render_js=request.render_js,
        follow_redirects=request.follow_redirects,
        max_depth=request.max_depth,
        timeout=request.timeout,
    )
    ssl_task = check_ssl(target, timeout=request.timeout)
    landing_task = fetch_landing_page_full(target, timeout=request.timeout)
    paths_task = scan_sensitive_paths(target, timeout=request.timeout)

    crawl_result, ssl_result, landing_result, paths_result = await asyncio.gather(
        crawl_task, ssl_task, landing_task, paths_task,
        return_exceptions=True,
    )

    # Handle crawl failure
    if isinstance(crawl_result, Exception):
        logger.exception("Crawl failed for %s", target)
        failed = DomainResult(
            target=target,
            scan_started_at=started,
            scan_finished_at=datetime.now(timezone.utc).isoformat(),
            error=str(crawl_result),
        )
        failed.fair_signals = compute_fair_signals(failed, scan_mode="full")
        return failed

    pages = crawl_result

    # Process SSL result
    if isinstance(ssl_result, Exception):
        logger.warning("SSL check failed for %s: %s", target, ssl_result)
        ssl_result = SSLCertResult(is_valid=False, issues=[f"Check failed: {ssl_result}"])

    # Process headers + cookies + HTML body
    if isinstance(landing_result, Exception):
        logger.warning("Landing page fetch failed for %s: %s", target, landing_result)
        resp_headers, resp_cookies, landing_html = {}, httpx.Cookies(), ""
    else:
        resp_headers, resp_cookies, landing_html = landing_result

    headers_result = analyze_headers(resp_headers)
    cookie_findings = analyze_cookies(resp_cookies)

    # Tech fingerprint + JS bundle mining (both derive from the landing HTML).
    tech_findings: list = []
    js_intel_result = None
    try:
        soup = BeautifulSoup(landing_html or "", "html.parser")
        meta: dict[str, str] = {}
        for tag in soup.find_all("meta"):
            name = (tag.get("name") or tag.get("property") or "").lower()
            content = tag.get("content") or ""
            if name and content:
                meta[name] = content
        script_urls = [t.get("src", "") for t in soup.find_all("script", src=True)]
        tech_findings = fingerprint_tech(
            html=landing_html,
            headers=resp_headers,
            cookies=resp_cookies,
            script_urls=script_urls,
            meta=meta,
        )
    except Exception as exc:
        logger.warning("Tech fingerprint failed for %s: %s", target, exc)

    try:
        js_intel_result = await mine_javascript(
            target, landing_html, timeout=request.timeout,
        )
    except Exception as exc:
        logger.warning("JS mining failed for %s: %s", target, exc)

    # Process sensitive paths
    if isinstance(paths_result, Exception):
        logger.warning("Path scan failed for %s: %s", target, paths_result)
        paths_result = []

    # Aggregate contacts, links, and secrets across all pages,
    # tracking which page URL each finding came from.
    email_sources: dict[str, list[str]] = {}
    phone_sources: dict[str, list[str]] = {}
    social_sources: dict[str, list[str]] = {}
    internal_links: set[str] = set()
    ext_link_sources: dict[str, dict] = {}   # url -> {anchor_text, found_on}
    all_secrets = []
    ioc_seen: set[tuple[str, str]] = set()  # (ioc_type, evidence) for dedup
    all_iocs = []

    for page in pages:
        page_url = page.url
        for email in page.contacts.emails:
            email_sources.setdefault(email, []).append(page_url)
        for phone in page.contacts.phone_numbers:
            phone_sources.setdefault(phone, []).append(page_url)
        for social in page.contacts.social_profiles:
            social_sources.setdefault(social, []).append(page_url)
        for link in page.links:
            if link.link_type == "internal":
                internal_links.add(link.url)
            else:
                entry = ext_link_sources.setdefault(
                    link.url, {"anchor_text": link.anchor_text, "found_on": []}
                )
                entry["found_on"].append(page_url)
        all_secrets.extend(page.secrets)
        for ioc in page.ioc_findings:
            key = (ioc.ioc_type, ioc.evidence)
            if key not in ioc_seen:
                ioc_seen.add(key)
                all_iocs.append(ioc)

    # Build provenance-tracked lists
    email_findings = [
        EmailFinding(email=e, found_on=sorted(set(urls)))
        for e, urls in sorted(email_sources.items())
    ]
    phone_findings = [
        PhoneFinding(phone=p, found_on=sorted(set(urls)))
        for p, urls in sorted(phone_sources.items())
    ]
    social_findings = [
        SocialFinding(url=s, platform=_detect_platform(s), found_on=sorted(set(urls)))
        for s, urls in sorted(social_sources.items())
    ]
    ext_link_findings = [
        ExternalLinkFinding(
            url=u, anchor_text=d["anchor_text"], found_on=sorted(set(d["found_on"])),
        )
        for u, d in sorted(ext_link_sources.items())
    ]

    # Flat contact list (backwards-compatible)
    flat_contacts = ContactInfo(
        emails=sorted(email_sources),
        phone_numbers=sorted(phone_sources),
        social_profiles=sorted(social_sources),
    )

    # Breach checks
    breaches = []
    if request.check_breaches:
        try:
            breaches = await check_breaches(domain, list(email_sources))
        except Exception as exc:
            logger.warning("Breach check failed for %s: %s", domain, exc)

    finished = datetime.now(timezone.utc).isoformat()

    cookie_issues_count = sum(1 for c in cookie_findings if c.issues)

    js_endpoints_count = (
        len(js_intel_result.api_endpoints) if js_intel_result else 0
    )

    domain_summary = DomainSummary(
        pages_scanned=len(pages),
        emails_found=len(email_findings),
        phone_numbers_found=len(phone_findings),
        social_profiles_found=len(social_findings),
        internal_links_found=len(internal_links),
        external_links_found=len(ext_link_findings),
        secrets_found=len(all_secrets),
        breaches_found=len(breaches),
        security_headers_grade=headers_result.grade,
        ssl_grade=ssl_result.grade,
        cookie_issues=cookie_issues_count,
        sensitive_paths_found=len(paths_result),
        ioc_findings=len(all_iocs),
        technologies_found=len(tech_findings),
        js_endpoints_found=js_endpoints_count,
    )

    result = DomainResult(
        target=target,
        scan_started_at=started,
        scan_finished_at=finished,
        summary=domain_summary,
        pages_scanned=len(pages),
        pages=pages,
        contacts=flat_contacts,
        emails=email_findings,
        phone_numbers=phone_findings,
        social_profiles=social_findings,
        internal_links=sorted(internal_links),
        external_links=ext_link_findings,
        secrets=all_secrets,
        breaches=breaches,
        security_headers=headers_result,
        ssl_certificate=ssl_result,
        cookies=cookie_findings,
        sensitive_paths=paths_result,
        ioc_findings=all_iocs,
        technologies=tech_findings,
        js_intel=js_intel_result,
        metadata={
            "domain": domain,
            "render_js": request.render_js,
            "max_depth": request.max_depth,
        },
    )
    result.fair_signals = compute_fair_signals(result, scan_mode="full")
    return result


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    """Perform a batch OSINT scan across one or more target domains."""
    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()

    targets = [_normalise_target(t) for t in request.targets]

    # Run all domain scans concurrently
    tasks = [_scan_single_target(t, request) for t in targets]
    domain_results: list[DomainResult] = await asyncio.gather(*tasks)

    finished = datetime.now(timezone.utc).isoformat()

    total_pages = sum(r.summary.pages_scanned for r in domain_results)
    total_secrets = sum(r.summary.secrets_found for r in domain_results)
    total_breaches = sum(r.summary.breaches_found for r in domain_results)

    top_summary = ScanSummary(
        targets=len(targets),
        pages_scanned=total_pages,
        emails_found=sum(r.summary.emails_found for r in domain_results),
        phone_numbers_found=sum(r.summary.phone_numbers_found for r in domain_results),
        social_profiles_found=sum(r.summary.social_profiles_found for r in domain_results),
        internal_links_found=sum(r.summary.internal_links_found for r in domain_results),
        external_links_found=sum(r.summary.external_links_found for r in domain_results),
        secrets_found=total_secrets,
        breaches_found=total_breaches,
        total_cookie_issues=sum(r.summary.cookie_issues for r in domain_results),
        total_sensitive_paths=sum(r.summary.sensitive_paths_found for r in domain_results),
        total_ioc_findings=sum(r.summary.ioc_findings for r in domain_results),
    )

    # Determine overall status
    errors = [r for r in domain_results if r.error]
    if len(errors) == len(domain_results):
        status = "failed"
    elif errors:
        status = "partial"
    else:
        status = "completed"

    return ScanResponse(
        scan_id=scan_id,
        status=status,
        started_at=started,
        finished_at=finished,
        summary=top_summary,
        total_targets=len(targets),
        total_pages_scanned=total_pages,
        total_secrets_found=total_secrets,
        total_breaches_found=total_breaches,
        results=domain_results,
    )


@app.post("/scan/quick")
async def quick_scan(request: ScanRequest) -> ScanResponse:
    """Quick scan – static fetch only, depth 0, no breach check."""
    request.render_js = False
    request.max_depth = 0
    request.check_breaches = False
    return await scan(request)


# ---------------------------------------------------------------------------
# Light-touch scan — exactly one GET per target (WAF-friendly)
# ---------------------------------------------------------------------------

async def _lighttouch_single_target(target: str, timeout: int) -> DomainResult:
    """Single-GET scan with a browser UA. No path probe, crawl, JS mine, or breach."""
    domain = _extract_domain(target)
    started = datetime.now(timezone.utc).isoformat()

    ssl_task = check_ssl(target, timeout=timeout)
    landing_task = fetch_landing_page_full(target, timeout=timeout, stealth=True)

    ssl_result, landing_result = await asyncio.gather(
        ssl_task, landing_task, return_exceptions=True,
    )

    if isinstance(ssl_result, Exception):
        logger.warning("SSL check failed for %s: %s", target, ssl_result)
        ssl_result = SSLCertResult(is_valid=False, issues=[f"Check failed: {ssl_result}"])

    if isinstance(landing_result, Exception) or not landing_result:
        logger.warning("Light-touch landing fetch failed for %s", target)
        resp_headers, resp_cookies, html = {}, httpx.Cookies(), ""
    else:
        resp_headers, resp_cookies, html = landing_result

    soup = BeautifulSoup(html or "", "html.parser")
    title, meta_desc, snippet = extract_page_metadata(soup)
    contacts = extract_contacts(soup, html)
    links = extract_links(soup, target)
    secrets = scan_secrets(html) if html else []
    iocs = scan_ioc(html, target) if html else []

    meta: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        name = (tag.get("name") or tag.get("property") or "").lower()
        content = tag.get("content") or ""
        if name and content:
            meta[name] = content
    script_urls = [t.get("src", "") for t in soup.find_all("script", src=True)]

    tech_findings = fingerprint_tech(
        html=html,
        headers=resp_headers,
        cookies=resp_cookies,
        script_urls=script_urls,
        meta=meta,
    )

    headers_result = analyze_headers(resp_headers)
    cookie_findings = analyze_cookies(resp_cookies)

    internal_links = sorted({l.url for l in links if l.link_type == "internal"})
    ext_link_findings = [
        ExternalLinkFinding(url=l.url, anchor_text=l.anchor_text, found_on=[target])
        for l in links if l.link_type == "external"
    ]
    email_findings = [
        EmailFinding(email=e, found_on=[target]) for e in sorted(set(contacts.emails))
    ]
    phone_findings = [
        PhoneFinding(phone=p, found_on=[target])
        for p in sorted(set(contacts.phone_numbers))
    ]
    social_findings = [
        SocialFinding(url=s, platform=_detect_platform(s), found_on=[target])
        for s in sorted(set(contacts.social_profiles))
    ]

    page = PageResult(
        url=target,
        status_code=int(resp_headers.get(":status", 0)) or (200 if html else None),
        title=title,
        meta_description=meta_desc,
        content_snippet=snippet,
        links=links,
        contacts=contacts,
        secrets=secrets,
        ioc_findings=iocs,
    )

    finished = datetime.now(timezone.utc).isoformat()

    summary = DomainSummary(
        pages_scanned=1 if html else 0,
        emails_found=len(email_findings),
        phone_numbers_found=len(phone_findings),
        social_profiles_found=len(social_findings),
        internal_links_found=len(internal_links),
        external_links_found=len(ext_link_findings),
        secrets_found=len(secrets),
        breaches_found=0,
        security_headers_grade=headers_result.grade,
        ssl_grade=ssl_result.grade,
        cookie_issues=sum(1 for c in cookie_findings if c.issues),
        sensitive_paths_found=0,
        ioc_findings=len(iocs),
        technologies_found=len(tech_findings),
        js_endpoints_found=0,
    )

    result = DomainResult(
        target=target,
        scan_started_at=started,
        scan_finished_at=finished,
        summary=summary,
        pages_scanned=1 if html else 0,
        pages=[page] if html else [],
        contacts=contacts,
        emails=email_findings,
        phone_numbers=phone_findings,
        social_profiles=social_findings,
        internal_links=internal_links,
        external_links=ext_link_findings,
        secrets=secrets,
        breaches=[],
        security_headers=headers_result,
        ssl_certificate=ssl_result,
        cookies=cookie_findings,
        sensitive_paths=[],
        ioc_findings=iocs,
        technologies=tech_findings,
        js_intel=None,
        metadata={"domain": domain, "mode": "lighttouch"},
        error=None if html else "landing page fetch failed",
    )
    result.fair_signals = compute_fair_signals(result, scan_mode="lighttouch")
    return result


class LightTouchRequest(ReconRequest):
    """Light-touch scan payload — inherits targets + timeout from ReconRequest."""


@app.post("/scan/lighttouch", response_model=ScanResponse)
async def lighttouch_scan(request: LightTouchRequest) -> ScanResponse:
    """WAF-friendly scan. ONE GET per target with a Chrome UA + TLS handshake.

    No path probing, no crawling, no headless browser, no <script src>
    fetches, no sourcemap recovery, no breach lookup. Everything we can
    derive from a single landing-page response is derived.
    """
    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()

    targets = [_normalise_target(t) for t in request.targets]
    domain_results = await asyncio.gather(
        *(_lighttouch_single_target(t, request.timeout) for t in targets)
    )
    finished = datetime.now(timezone.utc).isoformat()

    total_pages = sum(r.summary.pages_scanned for r in domain_results)
    total_secrets = sum(r.summary.secrets_found for r in domain_results)

    errors = [r for r in domain_results if r.error]
    if len(errors) == len(domain_results):
        status = "failed"
    elif errors:
        status = "partial"
    else:
        status = "completed"

    return ScanResponse(
        scan_id=scan_id,
        status=status,
        started_at=started,
        finished_at=finished,
        summary=ScanSummary(
            targets=len(targets),
            pages_scanned=total_pages,
            emails_found=sum(r.summary.emails_found for r in domain_results),
            phone_numbers_found=sum(r.summary.phone_numbers_found for r in domain_results),
            social_profiles_found=sum(r.summary.social_profiles_found for r in domain_results),
            internal_links_found=sum(r.summary.internal_links_found for r in domain_results),
            external_links_found=sum(r.summary.external_links_found for r in domain_results),
            secrets_found=total_secrets,
            breaches_found=0,
            total_cookie_issues=sum(r.summary.cookie_issues for r in domain_results),
            total_sensitive_paths=0,
            total_ioc_findings=sum(r.summary.ioc_findings for r in domain_results),
        ),
        total_targets=len(targets),
        total_pages_scanned=total_pages,
        total_secrets_found=total_secrets,
        total_breaches_found=0,
        results=domain_results,
    )


# ---------------------------------------------------------------------------
# Passive scan — zero traffic to the target (third-party sources only)
# ---------------------------------------------------------------------------

class PassiveRequest(ReconRequest):
    """Passive scan payload — optional seed emails to also check against HIBP."""

    emails: list = []  # list[str]; keep weak-typed so an empty JSON array is OK


async def _passive_single_target(
    target: str, emails: list[str], timeout: int,
) -> DomainResult:
    domain = _extract_domain(target)
    started = datetime.now(timezone.utc).isoformat()

    dns_task = query_dns(domain, timeout=timeout)
    ct_task = query_ct_logs(domain, timeout=timeout)
    rdap_task = query_rdap(domain, timeout=timeout)
    wayback_task = query_wayback(domain, timeout=timeout)
    breach_task = check_breaches(domain, emails or [])

    dns, ct, rdap, wayback, breaches = await asyncio.gather(
        dns_task, ct_task, rdap_task, wayback_task, breach_task,
        return_exceptions=True,
    )

    def _to_result(x, kind):
        """Coerce either a successful result or a raised exception into a
        typed result object with ``.error`` populated on failure. Keeps the
        response shape stable for Xano et al., and lets operators see why
        a passive scan produced no data. Falls back to the exception class
        name when ``str(exc)`` is empty so we never emit ``error=""``."""
        if isinstance(x, Exception):
            msg = str(x) or x.__class__.__name__
            logger.warning("Passive %s lookup failed for %s: %s", kind.__name__, domain, msg)
            return kind(domain=domain, error=msg)
        return x

    dns = _to_result(dns, DNSResult)
    ct = _to_result(ct, CTResult)
    rdap = _to_result(rdap, RDAPResult)
    wayback = _to_result(wayback, WaybackResult)
    if isinstance(breaches, Exception):
        logger.warning("Passive breach lookup failed for %s: %s", domain, breaches)
        breaches = []

    # Email security and IP enrichment run after DNS so they can reuse its data.
    mx_records = dns.mx_records if not dns.error else []
    a_records = dns.a_records if not dns.error else []

    try:
        email_sec = await asyncio.wait_for(
            query_email_security(domain, mx_records, timeout=timeout),
            timeout=timeout,
        )
    except Exception as exc:
        email_sec = EmailSecurityResult(domain=domain, error=str(exc))

    try:
        ip_enrich = await asyncio.wait_for(
            query_ip_enrichment(domain, a_records, timeout=timeout),
            timeout=timeout,
        )
    except Exception as exc:
        ip_enrich = IPEnrichmentResult(domain=domain, error=str(exc))

    passive = PassiveIntelResult(
        dns=dns, ct=ct, rdap=rdap, wayback=wayback,
        email_security=email_sec, ip_enrichment=ip_enrich, breaches=breaches,
    )

    # If every upstream source reported an error, surface that on
    # DomainResult.error so the caller doesn't mistake an egress-blocked
    # VPS for a blank target.
    if all(x.error for x in (dns, ct, rdap, wayback)):
        passive_error = (
            f"All passive sources failed for {domain}: "
            f"dns={dns.error}; ct={ct.error}; rdap={rdap.error}; "
            f"wayback={wayback.error}"
        )
    else:
        passive_error = None

    summary = DomainSummary(
        pages_scanned=0,
        breaches_found=len(breaches),
        subdomains_found=len(ct.subdomains),
        wayback_snapshots=wayback.snapshot_count,
    )

    result = DomainResult(
        target=target,
        scan_started_at=started,
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
        summary=summary,
        pages_scanned=0,
        pages=[],
        breaches=breaches,
        passive_intel=passive,
        metadata={"domain": domain, "mode": "passive"},
        error=passive_error,
    )
    result.fair_signals = compute_fair_signals(result, scan_mode="passive")
    return result


@app.post("/scan/passive", response_model=ScanResponse)
async def passive_scan(request: PassiveRequest) -> ScanResponse:
    """Fully passive scan. Touches **only** third-party sources.

    Sources: system DNS resolver, crt.sh (CT logs), rdap.org, archive.org,
    and HIBP (if HIBP_API_KEY is set). The target domain receives zero
    packets from this server.
    """
    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()

    targets = [_normalise_target(t) for t in request.targets]
    domain_results = await asyncio.gather(*(
        _passive_single_target(t, list(request.emails or []), request.timeout)
        for t in targets
    ))
    finished = datetime.now(timezone.utc).isoformat()

    total_breaches = sum(r.summary.breaches_found for r in domain_results)

    return ScanResponse(
        scan_id=scan_id,
        status="completed",
        started_at=started,
        finished_at=finished,
        summary=ScanSummary(
            targets=len(targets),
            pages_scanned=0,
            breaches_found=total_breaches,
        ),
        total_targets=len(targets),
        total_pages_scanned=0,
        total_secrets_found=0,
        total_breaches_found=total_breaches,
        results=domain_results,
    )
