"""Subdomain permutation enumeration and takeover detection.

Combines CT-log-discovered subdomains with a built-in permutation wordlist,
resolves DNS for each candidate, then checks CNAME targets against a
fingerprint database of cloud services known to be vulnerable to subdomain
takeover.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Any

import dns.exception
import dns.name
import dns.rdatatype
import dns.resolver
import httpx

from .config import DNS_LIFETIME, HTTP_TIMEOUT

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Takeover fingerprint database
# ---------------------------------------------------------------------------

TAKEOVER_SERVICES: dict[str, dict[str, Any]] = {
    "GitHub Pages": {
        "cnames": [".github.io"],
        "http_fingerprints": [
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "severity": "critical",
        "remediation": "Remove the dangling CNAME record or reclaim the GitHub Pages repository.",
    },
    "Amazon S3": {
        "cnames": [".s3.amazonaws.com", ".s3-website", ".s3.dualstack"],
        "http_fingerprints": [
            "NoSuchBucket",
            "The specified bucket does not exist",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or create the S3 bucket to reclaim it.",
    },
    "Heroku": {
        "cnames": [".herokuapp.com", ".herokudns.com"],
        "http_fingerprints": [
            "No such app",
            "herokucdn.com/error-pages",
            "no-such-app",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or create a Heroku app with the matching name.",
    },
    "Shopify": {
        "cnames": [".myshopify.com"],
        "http_fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left",
        ],
        "severity": "high",
        "remediation": "Remove the CNAME or reconfigure the Shopify store.",
    },
    "Netlify": {
        "cnames": [".netlify.app", ".netlify.com"],
        "http_fingerprints": [
            "Not Found - Request ID",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the Netlify site.",
    },
    "Azure Web Apps": {
        "cnames": [".azurewebsites.net"],
        "http_fingerprints": [
            "404 Web Site not found",
            "The resource you are looking for has been removed",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the Azure Web App.",
    },
    "Azure Traffic Manager": {
        "cnames": [".trafficmanager.net"],
        "http_fingerprints": [],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the Traffic Manager profile.",
    },
    "Azure CDN / Front Door": {
        "cnames": [".azureedge.net", ".azurefd.net"],
        "http_fingerprints": [
            "The resource you are looking for has been removed",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the Azure CDN endpoint.",
    },
    "Azure Blob Storage": {
        "cnames": [".blob.core.windows.net"],
        "http_fingerprints": [
            "BlobNotFound",
            "The specified container does not exist",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or create the blob container.",
    },
    "Azure Cloud App": {
        "cnames": [".cloudapp.azure.com", ".cloudapp.net"],
        "http_fingerprints": [],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the cloud service.",
    },
    "Fastly": {
        "cnames": [".fastly.net", ".fastlylb.net"],
        "http_fingerprints": [
            "Fastly error: unknown domain",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or configure the Fastly service.",
    },
    "Pantheon": {
        "cnames": [".pantheonsite.io"],
        "http_fingerprints": [
            "404 error unknown site",
            "The gods are wise",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the Pantheon site.",
    },
    "Fly.io": {
        "cnames": [".fly.dev"],
        "http_fingerprints": [
            "404 Not Found",
        ],
        "severity": "high",
        "remediation": "Remove the CNAME or deploy an app on Fly.io.",
    },
    "Surge.sh": {
        "cnames": [".surge.sh"],
        "http_fingerprints": [
            "project not found",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the Surge project.",
    },
    "Ghost": {
        "cnames": [".ghost.io"],
        "http_fingerprints": [
            "The thing you were looking for is no longer here",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the Ghost blog.",
    },
    "Zendesk": {
        "cnames": [".zendesk.com"],
        "http_fingerprints": [
            "Help Center Closed",
            "this help center no longer exists",
        ],
        "severity": "high",
        "remediation": "Remove the CNAME or reconfigure Zendesk.",
    },
    "WordPress.com": {
        "cnames": [".wordpress.com"],
        "http_fingerprints": [
            "Do you want to register",
            "doesn't exist",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the WordPress.com site.",
    },
    "Tumblr": {
        "cnames": [".tumblr.com"],
        "http_fingerprints": [
            "There's nothing here.",
            "Whatever you were looking for",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the Tumblr blog.",
    },
    "Vercel": {
        "cnames": [".vercel.app", ".now.sh"],
        "http_fingerprints": [
            "The deployment could not be found",
        ],
        "severity": "critical",
        "remediation": "Remove the CNAME or reclaim the Vercel deployment.",
    },
    "Cargo Collective": {
        "cnames": [".cargocollective.com", ".cargo.site"],
        "http_fingerprints": [
            "404 Not Found",
        ],
        "severity": "high",
        "remediation": "Remove the CNAME or reclaim the Cargo site.",
    },
    "Unbounce": {
        "cnames": [".unbounce.com", "unbouncepages.com"],
        "http_fingerprints": [
            "The requested URL was not found on this server",
        ],
        "severity": "high",
        "remediation": "Remove the CNAME or reclaim the Unbounce page.",
    },
    "HubSpot": {
        "cnames": [".hubspot.net", ".hs-sites.com"],
        "http_fingerprints": [
            "This page isn't available",
        ],
        "severity": "high",
        "remediation": "Remove the CNAME or reclaim the HubSpot page.",
    },
}

# ---------------------------------------------------------------------------
# Permutation wordlist
# ---------------------------------------------------------------------------

SUBDOMAIN_WORDLIST: list[str] = [
    # Infrastructure
    "api", "api-v1", "api-v2", "api2", "graphql", "rest", "rpc", "grpc",
    "gateway", "proxy", "edge", "lb", "loadbalancer",
    # Environments
    "dev", "development", "staging", "stage", "test", "testing", "qa",
    "uat", "preprod", "pre-prod", "prod", "production",
    "sandbox", "demo", "preview", "beta", "alpha", "canary", "nightly",
    # Web / Apps
    "app", "apps", "web", "www2", "www3", "portal", "dashboard",
    "admin", "administrator", "panel", "console", "manage", "management",
    "m", "mobile", "wap",
    # Mail
    "mail", "mail2", "smtp", "imap", "pop", "pop3", "mx", "webmail",
    "email", "exchange", "autodiscover",
    # Auth
    "auth", "login", "sso", "oauth", "id", "identity", "accounts",
    "signup", "register",
    # Content / Docs
    "blog", "docs", "documentation", "wiki", "help", "support", "faq",
    "kb", "knowledgebase", "status", "changelog",
    # Static / Media
    "cdn", "static", "assets", "media", "images", "img", "files",
    "upload", "uploads", "downloads", "content",
    # DevOps / CI
    "git", "gitlab", "bitbucket", "jenkins", "ci", "cd", "deploy",
    "build", "releases", "artifacts", "registry", "docker", "k8s",
    # Monitoring
    "grafana", "monitor", "monitoring", "metrics", "logs", "kibana",
    "elastic", "prometheus", "sentry", "alerts", "nagios", "zabbix",
    # Database
    "db", "database", "mysql", "postgres", "postgresql", "redis",
    "mongo", "mongodb", "sql", "phpmyadmin", "adminer",
    # Networking
    "vpn", "remote", "rdp", "ssh", "bastion", "jump",
    "ns", "ns1", "ns2", "ns3", "dns", "resolver",
    "ftp", "sftp",
    # Commerce / Business
    "shop", "store", "checkout", "payments", "pay", "billing",
    "crm", "erp", "invoice",
    # Internal
    "internal", "intranet", "corp", "corporate", "office", "hq",
    "staff", "hr", "people",
    # Collaboration
    "jira", "confluence", "slack", "chat", "meet", "video",
    # Legacy / Backup
    "backup", "bak", "old", "legacy", "archive", "temp", "tmp",
    "v1", "v2", "v3", "new", "next",
    # Security
    "waf", "firewall", "secure", "security", "vault", "secrets",
]

# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

_DNS_SEMAPHORE: asyncio.Semaphore | None = None


def _get_semaphore(concurrency: int = 50) -> asyncio.Semaphore:
    global _DNS_SEMAPHORE
    if _DNS_SEMAPHORE is None:
        _DNS_SEMAPHORE = asyncio.Semaphore(concurrency)
    return _DNS_SEMAPHORE


async def _resolve_subdomain(fqdn: str, timeout: int = DNS_LIFETIME) -> dict | None:
    """Resolve a single subdomain. Returns dict with records or None if dead."""
    sem = _get_semaphore()
    async with sem:
        loop = asyncio.get_running_loop()
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout

            a_records: list[str] = []
            cname_target: str = ""

            # CNAME first
            try:
                ans = await loop.run_in_executor(
                    None, lambda: resolver.resolve(fqdn, "CNAME")
                )
                cname_target = str(ans[0].target).rstrip(".")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.exception.DNSException):
                pass

            # A records
            try:
                ans = await loop.run_in_executor(
                    None, lambda: resolver.resolve(fqdn, "A")
                )
                a_records = [r.to_text() for r in ans]
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers,
                    dns.exception.DNSException):
                pass
            except dns.resolver.NXDOMAIN:
                if not cname_target:
                    return None

            if not a_records and not cname_target:
                return None

            return {
                "fqdn": fqdn,
                "a_records": a_records,
                "cname": cname_target,
            }

        except Exception:
            return None


async def _check_cname_dangling(cname: str, timeout: int = DNS_LIFETIME) -> bool:
    """Check if a CNAME target resolves. Returns True if dangling (NXDOMAIN)."""
    loop = asyncio.get_running_loop()
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        await loop.run_in_executor(None, lambda: resolver.resolve(cname, "A"))
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Service matching
# ---------------------------------------------------------------------------

def _match_service(cname: str) -> tuple[str, dict[str, Any]] | None:
    """Check if a CNAME target matches a known takeover-vulnerable service."""
    cname_lower = cname.lower()
    for service_name, info in TAKEOVER_SERVICES.items():
        for pattern in info["cnames"]:
            if cname_lower.endswith(pattern):
                return service_name, info
    return None


async def _verify_http(
    subdomain: str,
    fingerprints: list[str],
    *,
    timeout: int = HTTP_TIMEOUT,
) -> tuple[bool, list[str]]:
    """HTTP GET the subdomain and check body against fingerprints."""
    evidence: list[str] = []
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=False,
        ) as client:
            for scheme in ("https", "http"):
                try:
                    resp = await client.get(f"{scheme}://{subdomain}")
                    body = resp.text[:8192]
                    for fp in fingerprints:
                        if fp.lower() in body.lower():
                            evidence.append(f"HTTP {resp.status_code}: body contains '{fp}'")
                            return True, evidence
                    if resp.status_code in (404, 451):
                        evidence.append(f"HTTP {resp.status_code} from {scheme}://{subdomain}")
                    break
                except httpx.ConnectError:
                    evidence.append(f"Connection refused on {scheme}://{subdomain}")
                    continue
                except Exception:
                    continue
    except Exception:
        pass
    return bool(evidence), evidence


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def enumerate_subdomains(
    domain: str,
    known_subdomains: list[str] | None = None,
    *,
    timeout: int = DNS_LIFETIME,
) -> dict:
    """Enumerate subdomains via permutation wordlist + known subs.

    Returns dict with live_subdomains list and source counts.
    """
    from .models import SubdomainEnumResult

    candidates: dict[str, str] = {}

    # Add known subdomains (from CT logs, etc.)
    ct_count = 0
    for sub in (known_subdomains or []):
        sub = sub.strip().lower().rstrip(".")
        if sub and sub != domain and sub.endswith(f".{domain}"):
            candidates[sub] = "ct"
            ct_count += 1

    # Add C99 subdomain finder results
    c99_count = 0
    try:
        from .c99_client import find_subdomains as c99_find
        c99_subs = await c99_find(domain)
        for sub in c99_subs:
            sub = sub.strip().lower().rstrip(".")
            if sub and sub != domain and sub.endswith(f".{domain}") and sub not in candidates:
                candidates[sub] = "c99"
                c99_count += 1
    except Exception as exc:
        logger.debug("C99 subdomain lookup skipped: %s", exc)

    # Add permutation candidates
    perm_count = 0
    for prefix in SUBDOMAIN_WORDLIST:
        fqdn = f"{prefix}.{domain}"
        if fqdn not in candidates:
            candidates[fqdn] = "permutation"
            perm_count += 1

    tasks = [_resolve_subdomain(fqdn, timeout) for fqdn in candidates]
    results = await asyncio.gather(*tasks)

    live: list[str] = []
    resolved: list[dict] = []
    sources = {"ct_candidates": ct_count, "c99_candidates": c99_count, "permutation_candidates": perm_count}
    ct_live = 0
    c99_live = 0
    perm_live = 0

    for fqdn, result in zip(candidates.keys(), results):
        if result is not None:
            live.append(fqdn)
            resolved.append(result)
            src = candidates[fqdn]
            if src == "ct":
                ct_live += 1
            elif src == "c99":
                c99_live += 1
            else:
                perm_live += 1

    sources["ct_live"] = ct_live
    sources["c99_live"] = c99_live
    sources["permutation_live"] = perm_live

    return {
        "domain": domain,
        "live_subdomains": sorted(live),
        "resolved": resolved,
        "sources": sources,
    }


async def check_takeovers(
    resolved_subdomains: list[dict],
    *,
    http_timeout: int = HTTP_TIMEOUT,
    dns_timeout: int = DNS_LIFETIME,
) -> list:
    """Check resolved subdomains for takeover vulnerabilities."""
    from .models import SubdomainTakeoverFinding

    findings: list[SubdomainTakeoverFinding] = []
    http_sem = asyncio.Semaphore(10)

    async def _check_one(entry: dict) -> SubdomainTakeoverFinding | None:
        fqdn = entry["fqdn"]
        cname = entry.get("cname", "")
        if not cname:
            return None

        match = _match_service(cname)
        if match is None:
            return None

        service_name, service_info = match
        evidence = [f"CNAME: {fqdn} → {cname}", f"Service: {service_name}"]

        is_dangling = await _check_cname_dangling(cname, timeout=dns_timeout)
        if is_dangling:
            evidence.append(f"CNAME target {cname} returns NXDOMAIN (dangling)")

        fingerprints = service_info.get("http_fingerprints", [])
        http_match = False
        if fingerprints:
            async with http_sem:
                http_match, http_evidence = await _verify_http(
                    fqdn, fingerprints, timeout=http_timeout
                )
                evidence.extend(http_evidence)

        if is_dangling and http_match:
            status = "vulnerable"
            severity = service_info["severity"]
        elif is_dangling:
            status = "vulnerable"
            severity = service_info["severity"]
        elif http_match:
            status = "likely_vulnerable"
            severity = "high" if service_info["severity"] == "critical" else service_info["severity"]
        else:
            status = "service_detected"
            severity = "info"

        return SubdomainTakeoverFinding(
            subdomain=fqdn,
            cname_target=cname,
            vulnerable_service=service_name,
            status=status,
            severity=severity,
            evidence=evidence,
            remediation=service_info.get("remediation", "Remove the dangling CNAME record."),
        )

    tasks = [_check_one(entry) for entry in resolved_subdomains]
    results = await asyncio.gather(*tasks)
    for r in results:
        if r is not None:
            findings.append(r)

    findings.sort(key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity, 5))
    return findings


async def scan_subdomain_takeover(
    domain: str,
    known_subdomains: list[str] | None = None,
    *,
    dns_timeout: int = DNS_LIFETIME,
    http_timeout: int = HTTP_TIMEOUT,
) -> Any:
    """Full subdomain enumeration + takeover detection pipeline."""
    from .models import SubdomainEnumResult, SubdomainTakeoverResult

    start = time.monotonic()
    try:
        enum_data = await enumerate_subdomains(
            domain,
            known_subdomains=known_subdomains,
            timeout=dns_timeout,
        )
    except Exception as exc:
        logger.warning("Subdomain enumeration failed for %s: %s", domain, exc)
        return SubdomainTakeoverResult(
            domain=domain,
            enumeration=SubdomainEnumResult(domain=domain, error=str(exc)),
            error=str(exc),
            scan_duration_seconds=round(time.monotonic() - start, 2),
        )

    enum_result = SubdomainEnumResult(
        domain=domain,
        live_subdomains=enum_data["live_subdomains"],
        sources=enum_data["sources"],
    )

    resolved = enum_data.get("resolved", [])
    try:
        findings = await check_takeovers(
            resolved,
            http_timeout=http_timeout,
            dns_timeout=dns_timeout,
        )
    except Exception as exc:
        logger.warning("Takeover check failed for %s: %s", domain, exc)
        findings = []

    elapsed = round(time.monotonic() - start, 2)
    return SubdomainTakeoverResult(
        domain=domain,
        enumeration=enum_result,
        findings=findings,
        subdomains_checked=len(resolved),
        scan_duration_seconds=elapsed,
    )
