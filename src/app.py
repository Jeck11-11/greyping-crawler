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

from .config import NUCLEI_API_URL, PD_TOOLS_API_URL, SCAN_CONCURRENCY, XANO_WEBHOOK_URL
from .nuclei_webhook import nuclei_background_scan

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
from .crawler import crawl_domain, fetch_rendered_cookies
from .cve_lookup import enrich_cves_with_epss_kev, lookup_cves
from .attack_paths import analyze_attack_paths
from .easm_report import build_easm_report
from .fair_signals import compute_fair_signals
from .favicon import fetch_favicon
from .cloud_assets import discover_cloud_assets
from .port_scanner import scan_ports
from .screenshot import take_screenshot
from .c99_client import check_ip_reputation, check_url_reputation, detect_waf, find_subdomains, validate_email
from .postprocess import fill_not_found
from .middleware import APIKeyMiddleware, RateLimitMiddleware
from .module_status import nuclei_module_status
from .signal_evaluation import build_signal_evaluation, resolve_scan_profile
from .js_miner import mine_javascript
from .extractors import (
    classify_social_url,
    extract_contacts,
    extract_links,
    extract_page_metadata,
    normalize_phone_e164,
    region_for_tld,
)
from .ioc_scanner import scan_ioc
from .privacy_scanner import analyze_privacy_compliance
from .typosquatting import check_typosquatting
from .models import (
    AggregateRequest,
    AsyncScanAck,
    AsyncScanJobStatus,
    AsyncScanRow,
    BoardJobStatus,
    BoardReport,
    BoardReportResponse,
    BoardScanAck,
    BoardScanRequest,
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
    PrivacyComplianceResult,
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
    SubdomainEntry,
    TyposquattingResult,
    URLReputationResult,
    VulnerabilitiesGroup,
    WAFResult,
    WaybackResult,
)
from .passive_intel import (
    _clean_hostname,
    enumerate_spf,
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


def _screenshot_succeeded(ss: ScreenshotResult) -> bool:
    """A screenshot only counts as taken when real image data was captured.

    A Playwright-unavailable / navigation-failed result is an *attempt*, not a
    success — empty base64, zero dimensions, zero bytes, or any error all mean
    no image was produced.
    """
    return bool(
        ss.error is None
        and ss.image_base64
        and ss.size_bytes > 0
        and ss.width > 0
        and ss.height > 0
    )


def _finalize_risk_assessment(result: "DomainResult", scan_mode: str) -> None:
    """Build the authoritative scan profile, FAIR candidate signals, EASM report
    and the schema-2.0 signal_evaluation, wiring them consistently so no section
    can claim coverage the scan did not perform.
    """
    # At synchronous-response time active Nuclei scanning is out-of-band; only
    # count it completed if findings were actually attached (e.g. via webhook).
    nuclei = result.nuclei
    nuclei_status = "completed" if (nuclei and nuclei.findings) else "skipped"
    profile = resolve_scan_profile(scan_mode=scan_mode, nuclei_status=nuclei_status)
    result.scan_profile = profile

    fair = compute_fair_signals(result, scan_mode=scan_mode, scan_profile=profile)
    result.risk_assessment = RiskAssessmentGroup(fair_signals=fair)
    result.risk_assessment.easm_report = build_easm_report(
        result, scan_mode=scan_mode, scan_profile=profile,
    )
    result.signal_evaluation = build_signal_evaluation(fair, profile)

    report = result.risk_assessment.easm_report
    if report:
        result.summary.overall_grade = report.overall_grade
        result.summary.ransomware_susceptibility = report.ransomware_susceptibility.score


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
    c99_subs_task = find_subdomains(domain)
    waf_task = detect_waf(target)
    robots_task = fetch_and_parse_robots_sitemap(target, timeout=request.timeout)
    typosquat_task = check_typosquatting(domain, timeout=request.timeout)
    async def _no_cookies() -> list[dict]:
        return []
    rendered_cookies_task = fetch_rendered_cookies(target, timeout=request.timeout) if request.render_js else _no_cookies()

    async def _httpx_probe_task():
        if not PD_TOOLS_API_URL:
            return None
        from .httpx_client import run_httpx_probe
        return await run_httpx_probe([target], timeout=request.timeout)

    (crawl_result, ssl_result, landing_result, paths_result,
     dns_result, ct_result, rdap_result, wayback_result,
     favicon_result,
     port_scan_result, cloud_assets_result, c99_subs_result,
     waf_raw_result,
     robots_sitemap_result, typosquat_result,
     rendered_cookies_result,
     httpx_probe_result) = await asyncio.gather(
        crawl_task, ssl_task, landing_task, paths_task,
        dns_task, ct_task, rdap_task, wayback_task,
        favicon_task,
        port_scan_task, cloud_assets_task, c99_subs_task,
        waf_task,
        robots_task, typosquat_task,
        rendered_cookies_task,
        _httpx_probe_task(),
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
        _finalize_risk_assessment(failed, scan_mode="full")
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
    browser_cookies = rendered_cookies_result if isinstance(rendered_cookies_result, list) else []
    cookie_findings = analyze_cookies(resp_cookies, browser_cookies=browser_cookies)

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

    # Supply chain risk analysis (same landing HTML, zero requests).
    from .supply_chain import analyze_supply_chain
    supply_chain_result = None
    try:
        supply_chain_result = analyze_supply_chain(landing_html, target)
    except Exception as exc:
        logger.warning("Supply chain analysis failed for %s: %s", target, exc)

    # Merge httpx probe results (ran in Phase 1 gather).
    if isinstance(httpx_probe_result, Exception):
        logger.debug("httpx tech supplement failed for %s: %s", target, httpx_probe_result)
    elif httpx_probe_result:
        from .models import TechFinding
        existing_names = {t.name.lower() for t in tech_findings}
        for tech_name in httpx_probe_result[0].technologies:
            if tech_name.lower() not in existing_names:
                tech_findings.append(TechFinding(
                    name=tech_name,
                    categories=[],
                    confidence="medium",
                    evidence=["httpx-probe"],
                ))

    # Privacy compliance analysis (uses paths + tech + landing HTML)
    privacy_result: PrivacyComplianceResult | None = None
    try:
        _privacy_paths = paths_result if isinstance(paths_result, list) else []
        privacy_result = analyze_privacy_compliance(
            domain, _privacy_paths, tech_findings, landing_html,
        )
    except Exception as exc:
        logger.warning("Privacy analysis failed for %s: %s", target, exc)
        privacy_result = PrivacyComplianceResult(domain=domain, error=str(exc))

    # Process Phase 1 exception results (sync).
    if isinstance(favicon_result, Exception):
        logger.warning("Favicon fetch failed for %s: %s", target, favicon_result)
        favicon_result = None

    if isinstance(port_scan_result, Exception):
        logger.warning("Port scan failed for %s: %s", target, port_scan_result)
        port_scan_result = PortScanResult(target=domain, error=str(port_scan_result))

    if isinstance(cloud_assets_result, Exception):
        logger.warning("Cloud asset scan failed for %s: %s", target, cloud_assets_result)
        cloud_assets_result = CloudAssetResult(domain=domain, error=str(cloud_assets_result))

    if isinstance(typosquat_result, Exception):
        logger.warning("Typosquatting scan failed for %s: %s", target, typosquat_result)
        typosquat_result = TyposquattingResult(domain=domain, error=str(typosquat_result))

    takeover_result = None

    if isinstance(paths_result, Exception):
        logger.warning("Path scan failed for %s: %s", target, paths_result)
        paths_result = []

    robots_result, sitemap_result = None, None
    if isinstance(robots_sitemap_result, tuple):
        robots_result, sitemap_result = robots_sitemap_result
    elif isinstance(robots_sitemap_result, Exception):
        logger.warning("robots/sitemap parse failed for %s: %s", target, robots_sitemap_result)

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

    # DNS-based cloud service + database endpoint detection.
    if not dns_result.error:
        from .cloud_assets import detect_cloud_services_from_dns, detect_exposed_databases_from_dns
        cloud_svcs = detect_cloud_services_from_dns(
            cname_records=dns_result.cname_records,
            mx_records=dns_result.mx_records,
            txt_records=dns_result.txt_records,
        )
        db_findings = detect_exposed_databases_from_dns(
            cname_records=dns_result.cname_records,
        )
        cloud_assets_result.cloud_services = cloud_svcs + db_findings

    c99_subs = c99_subs_result if isinstance(c99_subs_result, list) else []
    if ct_result:
        # Single choke point for subdomains from BOTH sources (crt.sh + C99):
        # validate every hostname so markdown-wrapped / malformed values never
        # reach the output (e.g. "[www.x.com](https://www.x.com)"). Runs even when
        # C99 returned nothing, so crt.sh-only results are cleaned too. Note the
        # walrus keeps the CLEANED value, not the original.
        merged = {c for h in (ct_result.subdomains or []) if (c := _clean_hostname(h))}
        details: list[SubdomainEntry] = []
        for entry in c99_subs:
            host = _clean_hostname(entry.get("subdomain", ""))
            if not host:
                continue
            merged.add(host)
            details.append(SubdomainEntry(
                subdomain=host,
                ip=entry.get("ip"),
                cloudflare=entry.get("cloudflare"),
            ))
        ct_result.subdomains = sorted(merged)
        if details:
            ct_result.subdomain_details = details
        if c99_subs and ct_result.error:
            ct_result.error = None

    # Prepare inputs for Phase 2.
    mx_records = dns_result.mx_records if not dns_result.error else []
    a_records = dns_result.a_records if not dns_result.error else []
    a_ips = [r.address for r in a_records] if a_records else []
    primary_ip = a_ips[0] if a_ips else ""

    # Phase 2: JS mining, CVE lookup, email security, IP enrichment,
    # and reputation checks all run concurrently.
    async def _noop():
        return None

    js_coro = mine_javascript(target, landing_html, timeout=request.timeout)
    cve_coro = lookup_cves(tech_findings, timeout=request.timeout) if tech_findings else _noop()
    email_sec_coro = asyncio.wait_for(
        query_email_security(domain, mx_records, timeout=request.timeout),
        timeout=request.timeout,
    )
    ip_enrich_coro = asyncio.wait_for(
        query_ip_enrichment(domain, a_ips, timeout=request.timeout),
        timeout=request.timeout,
    )
    ip_rep_coro = check_ip_reputation(primary_ip) if primary_ip else _noop()
    url_rep_coro = check_url_reputation(target)

    (js_raw, cve_raw, email_sec_raw, ip_enrich_raw,
     ip_raw, url_raw) = await asyncio.gather(
        js_coro, cve_coro, email_sec_coro, ip_enrich_coro,
        ip_rep_coro, url_rep_coro,
        return_exceptions=True,
    )

    # Unpack JS mining + CVE results.
    cve_findings: list = []
    if isinstance(js_raw, Exception):
        logger.warning("JS mining failed for %s: %s", target, js_raw)
    else:
        js_intel_result = js_raw
    if isinstance(cve_raw, Exception):
        logger.warning("CVE lookup failed for %s: %s", target, cve_raw)
    elif isinstance(cve_raw, list):
        cve_findings = cve_raw

    if cve_findings:
        try:
            await enrich_cves_with_epss_kev(cve_findings)
        except Exception as exc:
            logger.warning("EPSS/KEV enrichment failed for %s: %s", target, exc)

    # Unpack email security + IP enrichment.
    email_sec = (
        email_sec_raw if not isinstance(email_sec_raw, Exception)
        else EmailSecurityResult(domain=domain, error=str(email_sec_raw))
    )
    ip_enrich = (
        ip_enrich_raw if not isinstance(ip_enrich_raw, Exception)
        else IPEnrichmentResult(domain=domain, error=str(ip_enrich_raw))
    )

    # SPF deep enumeration — runs after email_sec is available.
    if email_sec.spf.exists:
        try:
            spf_intel = await enumerate_spf(domain, email_sec.spf, timeout=request.timeout)
            email_sec.spf.intel = spf_intel
        except Exception as exc:
            logger.warning("SPF enumeration failed for %s: %s", domain, exc)

    dns_group = DNSGroup(
        records=dns_result, email_security=email_sec, ip_enrichment=ip_enrich,
    )
    passive_slim = PassiveIntelSlim(
        ct=ct_result, rdap=rdap_result, wayback=wayback_result,
    )

    # Unpack reputation results.
    ip_rep_result: IPReputationResult | None = None
    url_rep_result: URLReputationResult | None = None
    if primary_ip and isinstance(ip_raw, dict):
        ip_rep_result = IPReputationResult(
            ip=primary_ip,
            malicious=ip_raw.get("malicious", False),
            detections=ip_raw.get("details", []) if isinstance(ip_raw.get("details"), list) else [],
        )
    elif isinstance(ip_raw, Exception):
        logger.warning("IP reputation check failed for %s: %s", target, ip_raw)
    if isinstance(url_raw, dict):
        url_rep_result = URLReputationResult(
            url=target,
            blacklisted=url_raw.get("blacklisted", False),
            detections=url_raw.get("detections", []),
            sources_checked=url_raw.get("sources_checked", 0),
        )
    elif isinstance(url_raw, Exception):
        logger.warning("URL reputation check failed for %s: %s", target, url_raw)

    # C99 WAF detection
    waf_result: WAFResult | None = None
    if isinstance(waf_raw_result, dict):
        waf_result = WAFResult(
            url=target,
            detected=waf_raw_result.get("detected", False),
            firewall=waf_raw_result.get("firewall"),
        )
        # A vendor that is primarily a CDN (Cloudflare/Akamai/Fastly/etc.) being
        # present proves proxying, not that a WAF ruleset is enabled. Record the
        # CDN separately and leave WAF "not_assessed" unless the detector named a
        # dedicated WAF product.
        _fw = (waf_result.firewall or "").lower()
        _cdn_vendors = {"cloudflare", "akamai", "fastly", "imperva", "incapsula",
                        "cloudfront", "amazon", "azure front door", "google"}
        if waf_result.detected and any(v in _fw for v in _cdn_vendors):
            waf_result.cdn_detected = True
            waf_result.cdn_provider = waf_result.firewall or ""
            waf_result.reverse_proxy_detected = True
            waf_result.waf_detected = None
            waf_result.waf_detection_status = "not_assessed"
        elif waf_result.detected and waf_result.firewall:
            waf_result.waf_detected = True
            waf_result.waf_provider = waf_result.firewall
            waf_result.waf_detection_status = "detected"

        # Even when the WAF detector returns nothing, the resolved IP's ASN may
        # prove a CDN/reverse-proxy is fronting the site. Record that as CDN —
        # never as a WAF (which stays not_assessed without a ruleset signal).
        if not waf_result.cdn_detected:
            _cdn_hosts = {h.lower() for h in (ip_enrich.hosting_providers or [])}
            _cdn_match = next(
                (h for h in _cdn_hosts if any(v in h for v in _cdn_vendors)), ""
            )
            if _cdn_match:
                waf_result.cdn_detected = True
                waf_result.cdn_provider = _cdn_match.title()
                waf_result.reverse_proxy_detected = True
                if waf_result.waf_detection_status == "not_assessed":
                    waf_result.waf_detected = None
        if waf_result.detected and waf_result.firewall:
            existing_names = {t.name.lower() for t in tech_findings}
            if waf_result.firewall.lower() not in existing_names:
                from .models import TechFinding
                tech_findings.append(TechFinding(
                    name=waf_result.firewall,
                    categories=["waf"],
                    confidence="high",
                    evidence=["c99_firewalldetector"],
                ))

    # Aggregate contacts, links, and secrets across all pages,
    # tracking which page URL each finding came from.
    _tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    _region_cc, _region_country = region_for_tld(_tld)

    email_sources: dict[str, list[str]] = {}
    # Keyed by normalized E.164 value so formatting variants of the same number
    # collapse into one finding.
    phone_sources: dict[str, dict] = {}
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
            norm = normalize_phone_e164(phone, _region_cc, _region_country)
            key = norm["normalized_value"] or phone
            entry = phone_sources.setdefault(
                key,
                {"raw": norm["raw_value"], "normalized": norm["normalized_value"],
                 "country": norm["country"], "confidence": norm["confidence"], "found_on": []},
            )
            entry["found_on"].append(page_url)
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
        PhoneFinding(
            phone=key,
            raw_value=d["raw"],
            normalized_value=d["normalized"],
            country=d["country"],
            confidence=d["confidence"],
            found_on=sorted(set(d["found_on"])),
        )
        for key, d in sorted(phone_sources.items())
    ]
    social_findings = [
        SocialFinding(
            url=s,
            platform=detect_platform(s),
            link_type=classify_social_url(s),
            found_on=sorted(set(urls)),
        )
        for s, urls in sorted(social_sources.items())
    ]
    # Only organisation-owned profiles count as social profiles; share/tracking
    # buttons are reported separately and excluded from the profile total.
    organisation_social = [f for f in social_findings if f.link_type == "organisation_profile"]
    social_share_links = [f for f in social_findings if f.link_type in ("share_link", "tracking_link")]
    # Confident phone numbers only (bare national fragments are low-confidence).
    confident_phones = [f for f in phone_findings if f.confidence == "high"]
    ext_link_findings = []
    for u, d in sorted(ext_link_sources.items()):
        unique_pages = sorted(set(d["found_on"]))
        ext_link_findings.append(ExternalLinkFinding(
            url=u,
            anchor_text=d["anchor_text"],
            found_on=unique_pages[:MAX_FOUND_ON],
        ))

    # Email validation + breach checks run in parallel
    email_validations: list[EmailValidationResult] = []
    breaches = []
    discovered_emails = sorted(email_sources)[:20]

    async def _do_email_validation() -> list[EmailValidationResult]:
        if not discovered_emails:
            return []
        val_tasks = [validate_email(e) for e in discovered_emails]
        val_results = await asyncio.gather(*val_tasks, return_exceptions=True)
        results = []
        for raw in val_results:
            if isinstance(raw, dict):
                results.append(EmailValidationResult(
                    email=raw.get("email", ""),
                    valid=raw.get("valid"),
                    disposable=raw.get("disposable", False),
                    role_account=raw.get("role_account", False),
                    free_provider=raw.get("free_provider", False),
                ))
        return results

    async def _do_breach_check() -> list:
        if not request.check_breaches:
            return []
        return await check_breaches(domain, list(email_sources))

    val_raw, breach_raw = await asyncio.gather(
        _do_email_validation(), _do_breach_check(), return_exceptions=True,
    )
    if isinstance(val_raw, Exception):
        logger.warning("Email validation failed for %s: %s", domain, val_raw)
    else:
        email_validations = val_raw
    if isinstance(breach_raw, Exception):
        logger.warning("Breach check failed for %s: %s", domain, breach_raw)
    else:
        breaches = breach_raw

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
                # Keep every ScreenshotResult (success or failure) in the list so
                # the payload records the attempt; success is measured separately
                # via _screenshot_succeeded — a failed/empty capture is not "taken".
                if isinstance(ss, ScreenshotResult):
                    screenshots.append(ss)
        except Exception as exc:
            logger.warning("Screenshots failed for %s: %s", target, exc)

    screenshot_attempts = len(screenshots)
    screenshots_taken = sum(1 for ss in screenshots if _screenshot_succeeded(ss))
    screenshot_failures = screenshot_attempts - screenshots_taken

    finished = datetime.now(timezone.utc).isoformat()

    cookie_issues_count = sum(1 for c in cookie_findings if c.issues)

    js_endpoints_count = (
        len(js_intel_result.api_endpoints) if js_intel_result else 0
    )

    domain_summary = DomainSummary(
        pages_scanned=len(pages),
        emails_found=len(email_findings),
        phone_numbers_found=len(confident_phones),
        social_profiles_found=len(organisation_social),
        organisation_social_profiles=len(organisation_social),
        social_share_links=len(social_share_links),
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
        subdomains_found=len(ct_result.subdomains or []),
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
        cloud_buckets_found=(
            cloud_assets_result.publicly_exposed_buckets
            + cloud_assets_result.confirmed_owned_buckets
        ) if cloud_assets_result else 0,
        cloud_services_found=len(cloud_assets_result.cloud_services) if cloud_assets_result else 0,
        exposed_databases_found=sum(
            1 for s in (cloud_assets_result.cloud_services if cloud_assets_result else []) if s.is_database
        ),
        screenshot_attempts=screenshot_attempts,
        screenshots_taken=screenshots_taken,
        screenshot_failures=screenshot_failures,
        typosquat_candidates=len(typosquat_result.registered_candidates) if typosquat_result else 0,
        waf_detected=waf_result.firewall if waf_result and waf_result.detected else "",
        privacy_score=privacy_result.score if privacy_result else 0,
        consent_tool=privacy_result.consent_tool if privacy_result else "",
        spf_senders_found=len(email_sec.spf.intel.senders) if email_sec.spf.intel else 0,
        spf_services_found=len(email_sec.spf.intel.services_detected) if email_sec.spf.intel else 0,
        vulnerable_libraries=supply_chain_result.vulnerable_libraries if supply_chain_result else 0,
        scripts_without_sri=supply_chain_result.scripts_without_sri if supply_chain_result else 0,
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
        supply_chain=supply_chain_result,
        port_scan=port_scan_result,
        cloud_assets=cloud_assets_result,
        passive_intel=passive_slim,
        vulnerabilities=VulnerabilitiesGroup(
            nuclei=nuclei_result,
            cve_findings=cve_findings,
            subdomain_takeover=takeover_result,
        ),
        reputation=ReputationGroup(ip=ip_rep_result, url=url_rep_result),
        waf=waf_result,
        typosquatting=typosquat_result,
        privacy=privacy_result,
        email_validations=email_validations,
        screenshots=screenshots,
        favicon=favicon_result,
        robots_txt=robots_result,
        sitemap=sitemap_result,
        metadata={
            "domain": domain,
            "render_js": request.render_js,
            "max_depth": request.max_depth,
            **({"company_size": request.company_size.value} if request.company_size else {}),
        },
    )
    result.attack_paths = analyze_attack_paths(result)
    _finalize_risk_assessment(result, scan_mode="full")
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

    nuclei_status = "skipped"
    if NUCLEI_API_URL and XANO_WEBHOOK_URL:
        nuclei_status = "pending"
        asyncio.create_task(nuclei_background_scan(scan_id, domain_results))

    scan_profile = getattr(request, "scan_profile", "") or "passive_easm"
    nuclei_mod = nuclei_module_status(nuclei_status, scan_profile)
    for dr in domain_results:
        dr.metadata["nuclei_status"] = nuclei_status
        dr.metadata["scan_profile"] = scan_profile
        dr.metadata["active_vulnerability_scanning_included"] = (
            nuclei_mod.included_in_scan_profile
        )
        dr.metadata["nuclei_module"] = nuclei_mod.model_dump(mode="json")

    return ScanResponse(
        scan_id=scan_id,
        status=status,
        started_at=started,
        finished_at=finished,
        summary=top_summary,
        total_targets=len(targets),
        results=domain_results,
    )


# ---------------------------------------------------------------------------
# Board scan — async job: discover subdomains, full-scan each, aggregate
# ---------------------------------------------------------------------------

_BOARD_JOBS: dict[str, BoardJobStatus] = {}


def _evict_board_jobs() -> None:
    from .config import BOARD_JOBS_MAX
    while len(_BOARD_JOBS) > BOARD_JOBS_MAX:
        oldest = next(iter(_BOARD_JOBS))
        del _BOARD_JOBS[oldest]


@app.post("/scan/board", status_code=202, response_model=BoardScanAck)
async def board_scan(request: BoardScanRequest) -> BoardScanAck:
    """Start an async board scan. Returns immediately with a scan_id to poll."""
    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()
    domain = request.root_domain.strip().lower().lstrip("www.")

    job = BoardJobStatus(scan_id=scan_id, status="pending", root_domain=domain, started_at=started)
    _BOARD_JOBS[scan_id] = job
    _evict_board_jobs()

    asyncio.create_task(_run_board_job(scan_id, request))

    logger.info("Board scan queued for %s (scan_id=%s)", domain, scan_id)

    return BoardScanAck(
        scan_id=scan_id,
        status="pending",
        root_domain=domain,
        started_at=started,
        poll_url=f"/scan/board/{scan_id}",
        message=f"Board scan started for {domain}. Poll GET /scan/board/{scan_id} for progress.",
    )


@app.get("/scan/board/{scan_id}", response_model=BoardJobStatus)
async def board_scan_status(scan_id: str) -> BoardJobStatus:
    """Poll a running or completed board scan by scan_id."""
    job = _BOARD_JOBS.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Board scan {scan_id} not found.")
    return job


async def _run_board_job(scan_id: str, request: BoardScanRequest) -> None:
    """Background worker: discover subdomains, scan each, aggregate, webhook."""
    from .board_report import build_board_report
    from .nuclei_webhook import post_board_webhook
    from .subdomain_takeover import enumerate_subdomains

    job = _BOARD_JOBS[scan_id]
    domain = job.root_domain

    try:
        job.status = "running"

        ct_result = await query_ct_logs(domain, timeout=request.timeout)
        ct_subs = ct_result.subdomains if ct_result and not ct_result.error else []

        enum_result = await enumerate_subdomains(
            domain, known_subdomains=ct_subs, timeout=request.timeout,
        )
        live_subs: list[str] = enum_result.get("live_subdomains", [])

        all_targets = [f"https://{domain}"]
        for sub in live_subs:
            if sub != domain:
                all_targets.append(f"https://{sub}")

        if request.max_subdomains > 0:
            all_targets = all_targets[:1 + request.max_subdomains]

        job.subdomains_discovered = len(live_subs)
        job.targets_total = len(all_targets)

        logger.info(
            "Board scan %s: %d subdomains discovered, scanning %d targets",
            scan_id, job.subdomains_discovered, len(all_targets),
        )

        scan_req = ScanRequest(
            targets=["placeholder"],
            render_js=request.render_js,
            follow_redirects=request.follow_redirects,
            max_depth=request.max_depth,
            check_breaches=request.check_breaches,
            timeout=request.timeout,
            company_size=request.company_size,
        )

        sem = asyncio.Semaphore(SCAN_CONCURRENCY)

        async def _bounded(target: str) -> DomainResult | None:
            async with sem:
                try:
                    result = await _scan_single_target(target, scan_req)
                    job.targets_completed += 1
                    logger.info(
                        "Board scan %s: %d/%d completed (%s)",
                        scan_id, job.targets_completed, job.targets_total, target,
                    )
                    return result
                except Exception as exc:
                    job.targets_completed += 1
                    logger.warning("Board scan %s: target %s failed: %s", scan_id, target, exc)
                    return None

        raw_results = await asyncio.gather(*(_bounded(t) for t in all_targets))
        domain_results: list[DomainResult] = [r for r in raw_results if r is not None]

        board_report = build_board_report(
            domain, domain_results, subdomains_discovered=job.subdomains_discovered,
        )

        finished = datetime.now(timezone.utc).isoformat()

        errors = [r for r in domain_results if r.error]
        if not domain_results:
            status = "failed"
        elif errors:
            status = "partial"
        else:
            status = "completed"

        job.status = status
        job.finished_at = finished
        job.board_report = board_report
        job.results = domain_results

        logger.info(
            "Board scan %s finished: %s, %d targets scanned, estate grade %s",
            scan_id, status, len(domain_results), board_report.estate_grade,
        )

        await post_board_webhook(scan_id, domain, status, board_report, domain_results)

    except Exception as exc:
        logger.exception("Board scan %s crashed: %s", scan_id, exc)
        job.status = "failed"
        job.finished_at = datetime.now(timezone.utc).isoformat()
        job.error = str(exc)


# ---------------------------------------------------------------------------
# Async batch scan — scan a known list of targets in the background,
# webhook each result as it completes (no request timeout, nothing lost)
# ---------------------------------------------------------------------------

_SCAN_JOBS: dict[str, AsyncScanJobStatus] = {}


def _evict_scan_jobs() -> None:
    from .config import SCAN_JOBS_MAX
    while len(_SCAN_JOBS) > SCAN_JOBS_MAX:
        oldest = next(iter(_SCAN_JOBS))
        del _SCAN_JOBS[oldest]


@app.post("/scan/async", status_code=202, response_model=AsyncScanAck)
async def scan_async(request: ScanRequest) -> AsyncScanAck:
    """Start a background scan of many targets. Returns immediately with a scan_id.

    Each target's full result is POSTed to XANO_SCAN_WEBHOOK_URL as it finishes,
    so a 200+ host estate streams back over time instead of timing out a single
    synchronous request. Poll GET /scan/async/{scan_id} for progress.
    """
    targets = [validate_target(t) for t in request.targets]
    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()

    job = AsyncScanJobStatus(
        scan_id=scan_id,
        status="pending",
        started_at=started,
        targets_total=len(targets),
        rows=[AsyncScanRow(target=t) for t in targets],
    )
    _SCAN_JOBS[scan_id] = job
    _evict_scan_jobs()

    asyncio.create_task(_run_async_scan_job(scan_id, targets, request))

    logger.info("Async scan queued: %d targets (scan_id=%s)", len(targets), scan_id)

    return AsyncScanAck(
        scan_id=scan_id,
        status="pending",
        targets_total=len(targets),
        poll_url=f"/scan/async/{scan_id}",
        message=(
            f"Scan started for {len(targets)} target(s). Results are POSTed to the "
            f"scan webhook as they complete. Poll GET /scan/async/{scan_id} for progress."
        ),
    )


@app.get("/scan/async/{scan_id}", response_model=AsyncScanJobStatus)
async def scan_async_status(scan_id: str) -> AsyncScanJobStatus:
    """Poll a running or completed async batch scan by scan_id."""
    job = _SCAN_JOBS.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Async scan {scan_id} not found.")
    return job


async def _run_async_scan_job(
    scan_id: str,
    targets: list[str],
    request: ScanRequest,
) -> None:
    """Background worker: scan each target concurrently, webhook each result."""
    from .nuclei_webhook import post_scan_complete_webhook, post_scan_result_webhook

    job = _SCAN_JOBS[scan_id]
    row_by_target = {row.target: row for row in job.rows}

    try:
        job.status = "running"
        sem = asyncio.Semaphore(SCAN_CONCURRENCY)
        total = len(targets)

        async def _bounded(idx: int, target: str) -> None:
            async with sem:
                row = row_by_target.get(target)
                try:
                    result = await _scan_single_target(target, request)
                    if result.error:
                        job.targets_failed += 1
                        if row:
                            row.status = "failed"
                    else:
                        job.targets_completed += 1
                        if row:
                            row.status = "completed"
                            easm = result.easm_report
                            row.grade = easm.overall_grade if easm else ""
                except Exception as exc:
                    job.targets_failed += 1
                    if row:
                        row.status = "failed"
                    logger.warning("Async scan %s: target %s failed: %s", scan_id, target, exc)
                    return

                try:
                    delivered = await post_scan_result_webhook(
                        scan_id, result, index=idx, total=total,
                    )
                    if delivered:
                        job.delivered += 1
                except Exception as exc:
                    logger.warning(
                        "Async scan %s: webhook for %s failed: %s", scan_id, target, exc,
                    )

        await asyncio.gather(*(_bounded(i, t) for i, t in enumerate(targets)))

        job.status = "completed"
        job.finished_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Async scan %s finished: %d completed, %d failed, %d delivered",
            scan_id, job.targets_completed, job.targets_failed, job.delivered,
        )

        await post_scan_complete_webhook(
            scan_id,
            targets_total=total,
            targets_completed=job.targets_completed,
            targets_failed=job.targets_failed,
        )

    except Exception as exc:
        logger.exception("Async scan %s crashed: %s", scan_id, exc)
        job.status = "failed"
        job.finished_at = datetime.now(timezone.utc).isoformat()
        job.error = str(exc)


# ---------------------------------------------------------------------------
# Aggregate endpoint — accepts stored EASM data, returns board report
# ---------------------------------------------------------------------------

@app.post("/report/aggregate", response_model=BoardReport)
async def aggregate_report(request: AggregateRequest) -> BoardReport:
    """Aggregate pre-scanned EASM data into a board report.

    Accepts stored EASM report data from Xano (no re-scanning) and runs the
    board report aggregation: deduplication, grading, financial/ransomware
    aggregation, compliance posture.  Returns instantly.
    """
    from .board_report import build_board_report
    from .models import DomainResult, EASMReport, RiskAssessmentGroup

    domain_results: list[DomainResult] = []
    for sub in request.subdomains:
        easm = EASMReport(
            overall_grade=sub.overall_grade,
            prioritized_findings=sub.prioritized_findings,
            financial_impact=sub.financial_impact,
            ransomware_susceptibility=sub.ransomware_susceptibility,
            executive_summary=sub.executive_summary,
            confirmed_issues=sub.confirmed_issues,
            total_findings=sub.total_findings,
            compliance_summary=sub.compliance_summary,
        )
        dr = DomainResult(
            target=sub.target,
            risk_assessment=RiskAssessmentGroup(easm_report=easm),
        )
        domain_results.append(dr)

    board = build_board_report(
        request.root_domain,
        domain_results,
        subdomains_discovered=len(request.subdomains),
    )
    return board


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

async def _lighttouch_single_target(target: str, timeout: int, *, company_size: str | None = None) -> DomainResult:
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

    if email_sec.spf.exists:
        try:
            spf_intel = await enumerate_spf(domain, email_sec.spf, timeout=timeout)
            email_sec.spf.intel = spf_intel
        except Exception as exc:
            logger.warning("SPF enumeration failed for %s: %s", domain, exc)

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

    lt_supply_chain = None
    try:
        lt_supply_chain = analyze_supply_chain(html, target)
    except Exception as exc:
        logger.warning("Supply chain analysis failed for %s: %s", target, exc)

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
    _lt_tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    _lt_cc, _lt_country = region_for_tld(_lt_tld)
    _lt_phones: dict[str, dict] = {}
    for p in contacts.phone_numbers:
        n = normalize_phone_e164(p, _lt_cc, _lt_country)
        _lt_phones.setdefault(n["normalized_value"] or p, n)
    phone_findings = [
        PhoneFinding(
            phone=key, raw_value=n["raw_value"], normalized_value=n["normalized_value"],
            country=n["country"], confidence=n["confidence"], found_on=[target],
        )
        for key, n in sorted(_lt_phones.items())
    ]
    social_findings = [
        SocialFinding(
            url=s, platform=detect_platform(s), link_type=classify_social_url(s),
            found_on=[target],
        )
        for s in sorted(set(contacts.social_profiles))
    ]
    organisation_social = [f for f in social_findings if f.link_type == "organisation_profile"]
    social_share_links = [f for f in social_findings if f.link_type in ("share_link", "tracking_link")]
    confident_phones = [f for f in phone_findings if f.confidence == "high"]

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
        phone_numbers_found=len(confident_phones),
        social_profiles_found=len(organisation_social),
        organisation_social_profiles=len(organisation_social),
        social_share_links=len(social_share_links),
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
        vulnerable_libraries=lt_supply_chain.vulnerable_libraries if lt_supply_chain else 0,
        scripts_without_sri=lt_supply_chain.scripts_without_sri if lt_supply_chain else 0,
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
        supply_chain=lt_supply_chain,
        passive_intel=lt_passive_slim,
        metadata={
            "domain": domain,
            "mode": "lighttouch",
            **({"company_size": company_size} if company_size else {}),
        },
        error=None if html else "landing page fetch failed",
    )
    result.attack_paths = analyze_attack_paths(result)
    _finalize_risk_assessment(result, scan_mode="lighttouch")
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
            return await _lighttouch_single_target(
                t, request.timeout,
                company_size=request.company_size.value if request.company_size else None,
            )

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
    target: str, emails: list[str], timeout: int, *, company_size: str | None = None,
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

    if email_sec.spf.exists:
        try:
            spf_intel = await enumerate_spf(domain, email_sec.spf, timeout=timeout)
            email_sec.spf.intel = spf_intel
        except Exception as exc:
            logger.warning("SPF enumeration failed for %s: %s", domain, exc)

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
        metadata={
            "domain": domain,
            "mode": "passive",
            **({"company_size": company_size} if company_size else {}),
        },
        error=passive_error,
    )
    result.attack_paths = analyze_attack_paths(result)
    _finalize_risk_assessment(result, scan_mode="passive")
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
            return await _passive_single_target(
                t, list(request.emails or []), request.timeout,
                company_size=request.company_size.value if request.company_size else None,
            )

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
