"""FastAPI application – OSINT Reconnaissance API."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import Field

import httpx

from .config import SCAN_CONCURRENCY

from ._http_utils import (
    TargetValidationError,
    fetch_landing_page,
    fetch_landing_page_full,
    normalise_target,
    validate_target,
)
from ._link_utils import is_asset_url, is_social_url, normalise_ext_url, MAX_FOUND_ON
from ._social_utils import detect_platform
from .breach_checker import check_breaches
from .cookie_checker import analyze_cookies
from .crawler import crawl_domain
from .cve_lookup import lookup_cves
from .easm_report import build_easm_report
from .fair_signals import compute_fair_signals
from .favicon import fetch_favicon
from .subdomain_takeover import scan_subdomain_takeover
from .cloud_assets import discover_cloud_assets
from .port_scanner import scan_ports
from .screenshot import take_screenshot
from .c99_client import check_ip_reputation, check_url_reputation, validate_email
from .postprocess import fill_not_found
from .middleware import APIKeyMiddleware, RateLimitMiddleware
from .js_miner import mine_javascript
from .extractors import extract_contacts, extract_links, extract_page_metadata
from .ioc_scanner import scan_ioc
from .models import (
    CloudAssetResult,
    ContactsGroup,
    CTResult,
    DNSGroup,
    DNSResult,
    DomainResult,
    DomainSummary,
    EmailSecurityResult,
    EmailFinding,
    EmailValidationResult,
    ExternalLinkFinding,
    IPEnrichmentResult,
    IPReputationResult,
    JSIntelResult,
    LinksGroup,
    NucleiResult,
    PageResult,
    PagesSummary,
    PassiveIntelSlim,
    PhoneFinding,
    PortScanResult,
    RDAPResult,
    ReconRequest,
    ReputationGroup,
    RiskAssessmentGroup,
    ScanRequest,
    ScanResponse,
    ScanSummary,
    ScreenshotResult,
    SecurityGroup,
    SecurityHeadersResult,
    SocialFinding,
    SSLCertResult,
    URLReputationResult,
    VulnerabilitiesGroup,
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
from .robots_sitemap import fetch_and_parse_robots_sitemap
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
app.add_middleware(RateLimitMiddleware)
app.add_middleware(APIKeyMiddleware)

app.include_router(network_router.router)
app.include_router(content_router.router)
app.include_router(discovery_router.router)
app.include_router(intel_router.router)
app.include_router(passive_router.router)


@app.exception_handler(TargetValidationError)
async def _target_validation_handler(_request: Request, exc: TargetValidationError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


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

    # Run crawl, SSL check, landing-page fetch, sensitive-path scan,
    # passive intel (DNS, CT, RDAP, Wayback), and favicon concurrently.
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
    dns_task = query_dns(domain, timeout=request.timeout)
    ct_task = query_ct_logs(domain, timeout=request.timeout)
    rdap_task = query_rdap(domain, timeout=request.timeout)
    wayback_task = query_wayback(domain, timeout=request.timeout)
    favicon_task = fetch_favicon(target, timeout=request.timeout)
    port_scan_task = scan_ports(domain)
    cloud_assets_task = discover_cloud_assets(domain)

    (crawl_result, ssl_result, landing_result, paths_result,
     dns_result, ct_result, rdap_result, wayback_result,
     favicon_result,
     port_scan_result, cloud_assets_result) = await asyncio.gather(
        crawl_task, ssl_task, landing_task, paths_task,
        dns_task, ct_task, rdap_task, wayback_task,
        favicon_task,
        port_scan_task, cloud_assets_task,
        return_exceptions=True,
    )

    # Nuclei is a separate scan — use /recon/nuclei endpoint directly.
    nuclei_result = NucleiResult(target=target)

    # Handle crawl failure
    if isinstance(crawl_result, Exception):
        logger.exception("Crawl failed for %s", target)
        failed = DomainResult(
            target=target,
            scan_started_at=started,
            scan_finished_at=datetime.now(timezone.utc).isoformat(),
            error=str(crawl_result),
        )
        failed.risk_assessment = RiskAssessmentGroup(
            fair_signals=compute_fair_signals(failed, scan_mode="full"),
            easm_report=build_easm_report(failed, scan_mode="full"),
        )
        fill_not_found(failed)
        return failed

    pages = crawl_result

    # Process SSL result
    if isinstance(ssl_result, Exception):
        logger.warning("SSL check failed for %s: %s", target, ssl_result)
        ssl_result = SSLCertResult(cert_valid=False, issues=[f"Check failed: {ssl_result}"])

    # Process headers + cookies + HTML body
    if isinstance(landing_result, Exception):
        logger.warning("Landing page fetch failed for %s: %s", target, landing_result)
        resp_headers, resp_cookies, landing_html = {}, httpx.Cookies(), ""
    else:
        resp_headers, resp_cookies, landing_html = landing_result

    headers_result = analyze_headers(resp_headers)
    cookie_findings = analyze_cookies(resp_cookies)

    # Enrich SSL result with HSTS and final URL
    hsts_val = resp_headers.get("strict-transport-security", "")
    ssl_result.hsts_header_enabled = bool(hsts_val)
    ssl_result.final_url = target

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

    # CVE correlation from detected tech versions
    cve_findings: list = []
    if tech_findings:
        try:
            cve_findings = await lookup_cves(tech_findings, timeout=request.timeout)
        except Exception as exc:
            logger.warning("CVE lookup failed for %s: %s", target, exc)


    # Process favicon result
    if isinstance(favicon_result, Exception):
        logger.warning("Favicon fetch failed for %s: %s", target, favicon_result)
        favicon_result = None

    # Process port scan result
    if isinstance(port_scan_result, Exception):
        logger.warning("Port scan failed for %s: %s", target, port_scan_result)
        port_scan_result = PortScanResult(target=domain, error=str(port_scan_result))

    # Process cloud assets result
    if isinstance(cloud_assets_result, Exception):
        logger.warning("Cloud asset scan failed for %s: %s", target, cloud_assets_result)
        cloud_assets_result = CloudAssetResult(domain=domain, error=str(cloud_assets_result))

    # Subdomain takeover scan (uses CT-discovered subdomains)
    ct_subdomains = (
        ct_result.subdomains
        if not isinstance(ct_result, Exception) and ct_result and not ct_result.error
        else []
    )
    try:
        takeover_result = await scan_subdomain_takeover(
            domain, known_subdomains=ct_subdomains,
        )
    except Exception as exc:
        logger.warning("Takeover scan failed for %s: %s", target, exc)
        takeover_result = None

    # Process sensitive paths
    if isinstance(paths_result, Exception):
        logger.warning("Path scan failed for %s: %s", target, paths_result)
        paths_result = []

    # Fetch and parse robots.txt + sitemap.xml
    robots_result, sitemap_result = None, None
    try:
        robots_result, sitemap_result = await fetch_and_parse_robots_sitemap(
            target, timeout=request.timeout,
        )
    except Exception as exc:
        logger.warning("robots/sitemap parse failed for %s: %s", target, exc)

    # Process passive intel results
    def _passive_result(x, kind):
        if isinstance(x, Exception):
            msg = str(x) or x.__class__.__name__
            logger.warning("Passive %s failed for %s: %s", kind.__name__, domain, msg)
            return kind(domain=domain, error=msg)
        return x

    dns_result = _passive_result(dns_result, DNSResult)
    ct_result = _passive_result(ct_result, CTResult)
    rdap_result = _passive_result(rdap_result, RDAPResult)
    wayback_result = _passive_result(wayback_result, WaybackResult)

    # Email security + IP enrichment (depend on DNS data)
    mx_records = dns_result.mx_records if not dns_result.error else []
    a_records = dns_result.a_records if not dns_result.error else []
    a_ips = [r.address for r in a_records] if a_records else []

    try:
        email_sec = await asyncio.wait_for(
            query_email_security(domain, mx_records, timeout=request.timeout),
            timeout=request.timeout,
        )
    except Exception as exc:
        email_sec = EmailSecurityResult(domain=domain, error=str(exc))

    try:
        ip_enrich = await asyncio.wait_for(
            query_ip_enrichment(domain, a_ips, timeout=request.timeout),
            timeout=request.timeout,
        )
    except Exception as exc:
        ip_enrich = IPEnrichmentResult(domain=domain, error=str(exc))

    dns_group = DNSGroup(
        records=dns_result, email_security=email_sec, ip_enrichment=ip_enrich,
    )
    passive_slim = PassiveIntelSlim(
        ct=ct_result, rdap=rdap_result, wayback=wayback_result,
    )

    # C99 reputation checks (IP + URL, run concurrently)
    ip_rep_result: IPReputationResult | None = None
    url_rep_result: URLReputationResult | None = None
    try:
        primary_ip = a_ips[0] if a_ips else ""
        ip_rep_coro = check_ip_reputation(primary_ip) if primary_ip else asyncio.sleep(0)
        url_rep_coro = check_url_reputation(target)
        ip_raw, url_raw = await asyncio.gather(ip_rep_coro, url_rep_coro, return_exceptions=True)

        if primary_ip and isinstance(ip_raw, dict):
            ip_rep_result = IPReputationResult(
                ip=primary_ip,
                malicious=ip_raw.get("malicious", False),
                detections=ip_raw.get("details", []) if isinstance(ip_raw.get("details"), list) else [],
            )
        if isinstance(url_raw, dict):
            url_rep_result = URLReputationResult(
                url=target,
                blacklisted=url_raw.get("blacklisted", False),
                detections=url_raw.get("detections", []),
                sources_checked=url_raw.get("sources_checked", 0),
            )
    except Exception as exc:
        logger.warning("C99 reputation checks failed for %s: %s", target, exc)

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
                if not is_asset_url(link.url):
                    internal_links.add(link.url)
            elif not is_social_url(link.url):
                norm = normalise_ext_url(link.url)
                entry = ext_link_sources.setdefault(
                    norm, {"anchor_text": "", "found_on": []}
                )
                if link.anchor_text and not entry["anchor_text"]:
                    entry["anchor_text"] = link.anchor_text
                entry["found_on"].append(page_url)
        for secret in page.secrets:
            secret.found_on = page_url
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
        SocialFinding(url=s, platform=detect_platform(s), found_on=sorted(set(urls)))
        for s, urls in sorted(social_sources.items())
    ]
    ext_link_findings = []
    for u, d in sorted(ext_link_sources.items()):
        unique_pages = sorted(set(d["found_on"]))
        ext_link_findings.append(ExternalLinkFinding(
            url=u,
            anchor_text=d["anchor_text"],
            found_on=unique_pages[:MAX_FOUND_ON],
        ))

    # C99 email validation (up to 20 discovered emails)
    email_validations: list[EmailValidationResult] = []
    discovered_emails = sorted(email_sources)[:20]
    if discovered_emails:
        try:
            val_tasks = [validate_email(e) for e in discovered_emails]
            val_results = await asyncio.gather(*val_tasks, return_exceptions=True)
            for raw in val_results:
                if isinstance(raw, dict):
                    email_validations.append(EmailValidationResult(
                        email=raw.get("email", ""),
                        valid=raw.get("valid"),
                        disposable=raw.get("disposable", False),
                        role_account=raw.get("role_account", False),
                        free_provider=raw.get("free_provider", False),
                    ))
        except Exception as exc:
            logger.warning("Email validation failed for %s: %s", domain, exc)

    # Breach checks
    breaches = []
    if request.check_breaches:
        try:
            breaches = await check_breaches(domain, list(email_sources))
        except Exception as exc:
            logger.warning("Breach check failed for %s: %s", domain, exc)

    # Screenshots — admin paths and takeover pages
    from .config import SCREENSHOT_MAX_PER_SCAN
    _ADMIN_PATHS = frozenset({
        "/admin", "/wp-admin", "/wp-login.php", "/administrator",
        "/login", "/dashboard", "/phpmyadmin", "/cpanel",
    })
    screenshot_urls: list[str] = []
    for p in paths_result:
        if p.path in _ADMIN_PATHS and p.status_code == 200:
            screenshot_urls.append(p.url or f"{target.rstrip('/')}{p.path}")
    if takeover_result:
        for f in takeover_result.findings:
            if f.status == "vulnerable":
                screenshot_urls.append(f"https://{f.subdomain}")
    screenshot_urls = screenshot_urls[:SCREENSHOT_MAX_PER_SCAN]
    screenshots: list[ScreenshotResult] = []
    if screenshot_urls:
        try:
            ss_tasks = [take_screenshot(u) for u in screenshot_urls]
            ss_results = await asyncio.gather(*ss_tasks, return_exceptions=True)
            for ss in ss_results:
                if isinstance(ss, ScreenshotResult) and not ss.error:
                    screenshots.append(ss)
                elif isinstance(ss, ScreenshotResult):
                    screenshots.append(ss)
        except Exception as exc:
            logger.warning("Screenshots failed for %s: %s", target, exc)

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
        subdomains_found=len(ct_result.subdomains) if not ct_result.error else 0,
        wayback_snapshots=wayback_result.snapshot_count if not wayback_result.error else 0,
        robots_disallow_count=len(robots_result.disallow_rules) if robots_result else 0,
        sitemap_url_count=sitemap_result.url_count if sitemap_result else 0,
        nuclei_findings=len(nuclei_result.findings) if nuclei_result else 0,
        cve_count=len(cve_findings),
        favicon_hash=favicon_result.hash if favicon_result else None,
        takeover_findings=len(takeover_result.findings) if takeover_result else 0,
        ip_malicious=ip_rep_result.malicious if ip_rep_result else False,
        url_blacklisted=url_rep_result.blacklisted if url_rep_result else False,
        emails_validated=len(email_validations),
        open_ports=len(port_scan_result.open_ports) if port_scan_result else 0,
        risky_ports=sum(1 for p in (port_scan_result.open_ports if port_scan_result else []) if p.is_risky),
        cloud_buckets_found=len(cloud_assets_result.findings) if cloud_assets_result else 0,
        screenshots_taken=len(screenshots),
    )

    # Build page summary from the raw pages list
    from urllib.parse import urlparse as _urlparse
    _page_routes: set[str] = set()
    _page_notable: list[str] = []
    for _pg in pages:
        _page_routes.add(_urlparse(_pg.url).path.rstrip("/") or "/")
        if _pg.secrets or _pg.ioc_findings:
            _page_notable.append(_pg.url)

    result = DomainResult(
        target=target,
        scan_started_at=started,
        scan_finished_at=finished,
        summary=domain_summary,
        ssl=ssl_result,
        dns=dns_group,
        security=SecurityGroup(
            headers=headers_result,
            cookies=cookie_findings,
            sensitive_paths=paths_result,
            secrets=all_secrets,
            ioc_findings=all_iocs,
        ),
        contacts=ContactsGroup(
            emails=email_findings,
            phone_numbers=phone_findings,
            social_profiles=social_findings,
        ),
        links=LinksGroup(
            internal=sorted(internal_links),
            external=ext_link_findings,
        ),
        pages=PagesSummary(
            total=len(pages),
            notable=_page_notable[:10],
            routes=sorted(_page_routes),
        ),
        technologies=tech_findings,
        breaches=breaches,
        js_intel=js_intel_result,
        port_scan=port_scan_result,
        cloud_assets=cloud_assets_result,
        passive_intel=passive_slim,
        vulnerabilities=VulnerabilitiesGroup(
            nuclei=nuclei_result,
            cve_findings=cve_findings,
            subdomain_takeover=takeover_result,
        ),
        reputation=ReputationGroup(ip=ip_rep_result, url=url_rep_result),
        email_validations=email_validations,
        screenshots=screenshots,
        favicon=favicon_result,
        robots_txt=robots_result,
        sitemap=sitemap_result,
        metadata={
            "domain": domain,
            "render_js": request.render_js,
            "max_depth": request.max_depth,
        },
    )
    result.risk_assessment = RiskAssessmentGroup(
        fair_signals=compute_fair_signals(result, scan_mode="full"),
        easm_report=build_easm_report(result, scan_mode="full"),
    )
    fill_not_found(result)
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

    targets = [validate_target(t) for t in request.targets]

    # Run domain scans concurrently, bounded by SCAN_CONCURRENCY
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)

    async def _bounded_scan(t: str) -> DomainResult:
        async with sem:
            return await _scan_single_target(t, request)

    domain_results: list[DomainResult] = await asyncio.gather(
        *(_bounded_scan(t) for t in targets)
    )

    finished = datetime.now(timezone.utc).isoformat()

    top_summary = ScanSummary(
        targets=len(targets),
        pages_scanned=sum(r.summary.pages_scanned for r in domain_results),
        emails_found=sum(r.summary.emails_found for r in domain_results),
        phone_numbers_found=sum(r.summary.phone_numbers_found for r in domain_results),
        social_profiles_found=sum(r.summary.social_profiles_found for r in domain_results),
        internal_links_found=sum(r.summary.internal_links_found for r in domain_results),
        external_links_found=sum(r.summary.external_links_found for r in domain_results),
        secrets_found=sum(r.summary.secrets_found for r in domain_results),
        breaches_found=sum(r.summary.breaches_found for r in domain_results),
        total_cookie_issues=sum(r.summary.cookie_issues for r in domain_results),
        total_sensitive_paths=sum(r.summary.sensitive_paths_found for r in domain_results),
        total_ioc_findings=sum(r.summary.ioc_findings for r in domain_results),
    )

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
    dns_task = query_dns(domain, timeout=timeout)
    ct_task = query_ct_logs(domain, timeout=timeout)
    rdap_task = query_rdap(domain, timeout=timeout)
    wayback_task = query_wayback(domain, timeout=timeout)

    (ssl_result, landing_result,
     dns_result, ct_result, rdap_result, wayback_result) = await asyncio.gather(
        ssl_task, landing_task,
        dns_task, ct_task, rdap_task, wayback_task,
        return_exceptions=True,
    )

    if isinstance(ssl_result, Exception):
        logger.warning("SSL check failed for %s: %s", target, ssl_result)
        ssl_result = SSLCertResult(cert_valid=False, issues=[f"Check failed: {ssl_result}"])

    def _pr(x, kind):
        if isinstance(x, Exception):
            msg = str(x) or x.__class__.__name__
            logger.warning("Passive %s failed for %s: %s", kind.__name__, domain, msg)
            return kind(domain=domain, error=msg)
        return x

    dns_result = _pr(dns_result, DNSResult)
    ct_result = _pr(ct_result, CTResult)
    rdap_result = _pr(rdap_result, RDAPResult)
    wayback_result = _pr(wayback_result, WaybackResult)

    mx_records = dns_result.mx_records if not dns_result.error else []
    a_records_dns = dns_result.a_records if not dns_result.error else []
    a_ips_dns = [r.address for r in a_records_dns] if a_records_dns else []

    try:
        email_sec = await asyncio.wait_for(
            query_email_security(domain, mx_records, timeout=timeout), timeout=timeout,
        )
    except Exception as exc:
        email_sec = EmailSecurityResult(domain=domain, error=str(exc))

    try:
        ip_enrich = await asyncio.wait_for(
            query_ip_enrichment(domain, a_ips_dns, timeout=timeout), timeout=timeout,
        )
    except Exception as exc:
        ip_enrich = IPEnrichmentResult(domain=domain, error=str(exc))

    lt_dns_group = DNSGroup(
        records=dns_result, email_security=email_sec, ip_enrichment=ip_enrich,
    )
    lt_passive_slim = PassiveIntelSlim(
        ct=ct_result, rdap=rdap_result, wayback=wayback_result,
    )

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
    for s in secrets:
        s.found_on = target
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

    # Enrich SSL result with HSTS and final URL
    hsts_lt = resp_headers.get("strict-transport-security", "")
    ssl_result.hsts_header_enabled = bool(hsts_lt)
    ssl_result.final_url = target

    internal_links = sorted({l.url for l in links if l.link_type == "internal" and not is_asset_url(l.url)})
    ext_seen: dict[str, ExternalLinkFinding] = {}
    for l in links:
        if l.link_type != "external" or is_social_url(l.url):
            continue
        norm = normalise_ext_url(l.url)
        if norm not in ext_seen:
            ext_seen[norm] = ExternalLinkFinding(
                url=norm, anchor_text=l.anchor_text, found_on=[target],
            )
        elif l.anchor_text and not ext_seen[norm].anchor_text:
            ext_seen[norm].anchor_text = l.anchor_text
    ext_link_findings = sorted(ext_seen.values(), key=lambda x: x.url)
    email_findings = [
        EmailFinding(email=e, found_on=[target]) for e in sorted(set(contacts.emails))
    ]
    phone_findings = [
        PhoneFinding(phone=p, found_on=[target])
        for p in sorted(set(contacts.phone_numbers))
    ]
    social_findings = [
        SocialFinding(url=s, platform=detect_platform(s), found_on=[target])
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

    from urllib.parse import urlparse as _urlparse
    _lt_routes = [_urlparse(page.url).path.rstrip("/") or "/"] if html else []

    result = DomainResult(
        target=target,
        scan_started_at=started,
        scan_finished_at=finished,
        summary=summary,
        ssl=ssl_result,
        dns=lt_dns_group,
        security=SecurityGroup(
            headers=headers_result,
            cookies=cookie_findings,
            secrets=secrets,
            ioc_findings=iocs,
        ),
        contacts=ContactsGroup(
            emails=email_findings,
            phone_numbers=phone_findings,
            social_profiles=social_findings,
        ),
        links=LinksGroup(
            internal=internal_links,
            external=ext_link_findings,
        ),
        pages=PagesSummary(
            total=1 if html else 0,
            routes=_lt_routes,
        ),
        technologies=tech_findings,
        passive_intel=lt_passive_slim,
        metadata={"domain": domain, "mode": "lighttouch"},
        error=None if html else "landing page fetch failed",
    )
    result.risk_assessment = RiskAssessmentGroup(
        fair_signals=compute_fair_signals(result, scan_mode="lighttouch"),
        easm_report=build_easm_report(result, scan_mode="lighttouch"),
    )
    fill_not_found(result)
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

    targets = [validate_target(t) for t in request.targets]
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)

    async def _bounded_lt(t: str) -> DomainResult:
        async with sem:
            return await _lighttouch_single_target(t, request.timeout)

    domain_results = await asyncio.gather(
        *(_bounded_lt(t) for t in targets)
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
        results=domain_results,
    )


# ---------------------------------------------------------------------------
# Passive scan — zero traffic to the target (third-party sources only)
# ---------------------------------------------------------------------------

class PassiveRequest(ReconRequest):
    """Passive scan payload — optional seed emails to also check against HIBP."""

    emails: list = Field(default_factory=list, max_length=100)


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
    a_ips = [r.address for r in a_records] if a_records else []

    try:
        email_sec = await asyncio.wait_for(
            query_email_security(domain, mx_records, timeout=timeout),
            timeout=timeout,
        )
    except Exception as exc:
        email_sec = EmailSecurityResult(domain=domain, error=str(exc))

    try:
        ip_enrich = await asyncio.wait_for(
            query_ip_enrichment(domain, a_ips, timeout=timeout),
            timeout=timeout,
        )
    except Exception as exc:
        ip_enrich = IPEnrichmentResult(domain=domain, error=str(exc))

    p_dns_group = DNSGroup(
        records=dns, email_security=email_sec, ip_enrichment=ip_enrich,
    )
    p_passive_slim = PassiveIntelSlim(ct=ct, rdap=rdap, wayback=wayback)

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
        sensitive_paths_found=0,
    )

    result = DomainResult(
        target=target,
        scan_started_at=started,
        scan_finished_at=datetime.now(timezone.utc).isoformat(),
        summary=summary,
        dns=p_dns_group,
        breaches=breaches,
        passive_intel=p_passive_slim,
        metadata={"domain": domain, "mode": "passive"},
        error=passive_error,
    )
    result.risk_assessment = RiskAssessmentGroup(
        fair_signals=compute_fair_signals(result, scan_mode="passive"),
        easm_report=build_easm_report(result, scan_mode="passive"),
    )
    fill_not_found(result)
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

    targets = [validate_target(t) for t in request.targets]
    sem = asyncio.Semaphore(SCAN_CONCURRENCY)

    async def _bounded_passive(t: str) -> DomainResult:
        async with sem:
            return await _passive_single_target(t, list(request.emails or []), request.timeout)

    domain_results = await asyncio.gather(*(
        _bounded_passive(t) for t in targets
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
        results=domain_results,
    )
