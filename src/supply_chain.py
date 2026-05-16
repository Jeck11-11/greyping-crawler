"""Third-party supply chain risk analysis.

Identifies external JavaScript and CSS resources loaded by a page, checks
for Subresource Integrity (SRI) attributes, detects known vulnerable
library versions from URL filenames, and classifies CDN providers.

Zero HTTP requests — works entirely from already-fetched HTML.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .models import SupplyChainResult, ThirdPartyResource

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CDN provider classification
# ---------------------------------------------------------------------------

_CDN_PROVIDERS: list[tuple[str, str]] = [
    ("cdn.jsdelivr.net", "jsDelivr"),
    ("cdnjs.cloudflare.com", "Cloudflare CDNJS"),
    ("unpkg.com", "unpkg"),
    ("ajax.googleapis.com", "Google Hosted Libraries"),
    ("fonts.googleapis.com", "Google Fonts"),
    ("fonts.gstatic.com", "Google Fonts"),
    ("stackpath.bootstrapcdn.com", "BootstrapCDN"),
    ("maxcdn.bootstrapcdn.com", "BootstrapCDN"),
    ("cdn.bootstrapcdn.com", "BootstrapCDN"),
    ("code.jquery.com", "jQuery CDN"),
    ("use.fontawesome.com", "Font Awesome"),
    ("kit.fontawesome.com", "Font Awesome"),
    ("cdn.tailwindcss.com", "Tailwind CSS"),
    ("cdn.cloudflare.com", "Cloudflare"),
    ("ga.jspm.io", "jspm"),
    ("esm.sh", "esm.sh"),
    ("cdn.skypack.dev", "Skypack"),
    ("polyfill.io", "Polyfill.io (COMPROMISED)"),
    ("cdn.polyfill.io", "Polyfill.io (COMPROMISED)"),
]

_CDN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"cloudfront\.net$"), "AWS CloudFront"),
    (re.compile(r"amazonaws\.com$"), "AWS"),
    (re.compile(r"azureedge\.net$"), "Azure CDN"),
    (re.compile(r"akamaized\.net$"), "Akamai"),
    (re.compile(r"fastly\.net$"), "Fastly"),
]


def _classify_provider(hostname: str) -> str:
    h = hostname.lower()
    for domain, name in _CDN_PROVIDERS:
        if h == domain or h.endswith("." + domain):
            return name
    for pat, name in _CDN_PATTERNS:
        if pat.search(h):
            return name
    return "unknown"


# ---------------------------------------------------------------------------
# Vulnerable library database
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> tuple[int, ...]:
    parts: list[int] = []
    for segment in v.split("."):
        digits = ""
        for ch in segment:
            if ch.isdigit():
                digits += ch
            else:
                break
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _version_lt(version: str, threshold: str) -> bool:
    return _parse_version(version) < _parse_version(threshold)


_VULN_DB: list[dict[str, str]] = [
    {
        "name": "jQuery",
        "url_pattern": r"jquery[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "3.5.0",
        "cve": "CVE-2020-11022",
        "severity": "high",
    },
    {
        "name": "jQuery UI",
        "url_pattern": r"jquery[-.]ui[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "1.13.0",
        "cve": "CVE-2021-41184",
        "severity": "high",
    },
    {
        "name": "AngularJS",
        "url_pattern": r"angular(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "1.8.0",
        "cve": "CVE-2022-25869",
        "severity": "high",
    },
    {
        "name": "Bootstrap",
        "url_pattern": r"bootstrap(?:\.bundle)?(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "3.4.1",
        "cve": "CVE-2019-8331",
        "severity": "medium",
    },
    {
        "name": "Lodash",
        "url_pattern": r"lodash(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "4.17.21",
        "cve": "CVE-2021-23337",
        "severity": "high",
    },
    {
        "name": "Moment.js",
        "url_pattern": r"moment(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "2.29.4",
        "cve": "CVE-2022-31129",
        "severity": "high",
    },
    {
        "name": "Handlebars",
        "url_pattern": r"handlebars(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "4.7.7",
        "cve": "CVE-2021-23369",
        "severity": "high",
    },
    {
        "name": "DOMPurify",
        "url_pattern": r"(?:dompurify|purify)(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "2.3.6",
        "cve": "CVE-2022-23519",
        "severity": "high",
    },
    {
        "name": "highlight.js",
        "url_pattern": r"highlight(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "10.4.1",
        "cve": "CVE-2020-26237",
        "severity": "medium",
    },
    {
        "name": "Vue.js",
        "url_pattern": r"vue(?:\.runtime)?(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "2.6.14",
        "cve": "CVE-2024-6783",
        "severity": "medium",
    },
    {
        "name": "Backbone.js",
        "url_pattern": r"backbone(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "1.4.0",
        "cve": "CVE-2016-9877",
        "severity": "medium",
    },
    {
        "name": "Dojo",
        "url_pattern": r"dojo(?:\.min)?[-@/.](?P<version>\d+\.\d+\.\d+)",
        "vulnerable_below": "1.16.4",
        "cve": "CVE-2021-23450",
        "severity": "high",
    },
]

_COMPILED_VULN_DB = [
    {**entry, "_re": re.compile(entry["url_pattern"], re.IGNORECASE)}
    for entry in _VULN_DB
]


def _check_vulnerable(url: str) -> tuple[str, str, str, str]:
    """Return (library, version, cve, severity) or empty strings."""
    for entry in _COMPILED_VULN_DB:
        m = entry["_re"].search(url)
        if m:
            version = m.group("version")
            if _version_lt(version, entry["vulnerable_below"]):
                return entry["name"], version, entry["cve"], entry["severity"]
            return entry["name"], version, "", ""
    return "", "", "", ""


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _is_external(url: str, target_domain: str) -> bool:
    host = (urlparse(url).hostname or "").lower().lstrip("www.")
    base = target_domain.lower().lstrip("www.")
    if not host:
        return False
    return not (host == base or host.endswith("." + base))


def _extract_scripts(soup: BeautifulSoup, base_url: str) -> list[tuple[str, bool]]:
    results: list[tuple[str, bool]] = []
    for tag in soup.find_all("script", src=True):
        src = tag.get("src") or ""
        if not src or src.startswith(("data:", "javascript:", "about:")):
            continue
        results.append((urljoin(base_url, src), bool(tag.get("integrity"))))
    return results


def _extract_stylesheets(soup: BeautifulSoup, base_url: str) -> list[tuple[str, bool]]:
    results: list[tuple[str, bool]] = []
    for tag in soup.find_all("link", rel=lambda v: v and "stylesheet" in v):
        href = tag.get("href") or ""
        if not href or href.startswith(("data:", "javascript:", "about:")):
            continue
        results.append((urljoin(base_url, href), bool(tag.get("integrity"))))
    return results


def analyze_supply_chain(html: str | None, target: str) -> SupplyChainResult | None:
    """Analyze landing page HTML for third-party supply chain risks."""
    if not html:
        return None

    target_domain = (urlparse(target).hostname or "").lower().lstrip("www.")
    if not target_domain:
        return None

    soup = BeautifulSoup(html, "html.parser")

    scripts = _extract_scripts(soup, target)
    stylesheets = _extract_stylesheets(soup, target)

    resources: list[ThirdPartyResource] = []
    providers_set: set[str] = set()
    scripts_no_sri = 0
    stylesheets_no_sri = 0
    vuln_count = 0

    for url, has_sri in scripts:
        if not _is_external(url, target_domain):
            continue

        hostname = (urlparse(url).hostname or "").lower()
        provider = _classify_provider(hostname)
        providers_set.add(provider)

        library, version, cve, _ = _check_vulnerable(url)
        is_vuln = bool(cve)
        if is_vuln:
            vuln_count += 1
        if not has_sri:
            scripts_no_sri += 1

        issues: list[str] = []
        if is_vuln:
            issues.append(f"Known vulnerable: {library} {version} ({cve})")
        if "COMPROMISED" in provider:
            issues.append(f"Loaded from compromised provider: {provider}")
        if not has_sri:
            issues.append("No Subresource Integrity (SRI) attribute")

        risk = "high" if (is_vuln or "COMPROMISED" in provider) else ("medium" if not has_sri else "info")

        resources.append(ThirdPartyResource(
            url=url,
            resource_type="script",
            provider=provider,
            library=library,
            version=version,
            has_sri=has_sri,
            risk=risk,
            issues=issues,
        ))

    for url, has_sri in stylesheets:
        if not _is_external(url, target_domain):
            continue

        hostname = (urlparse(url).hostname or "").lower()
        provider = _classify_provider(hostname)
        providers_set.add(provider)

        issues_ss: list[str] = []
        if not has_sri:
            stylesheets_no_sri += 1
            issues_ss.append("No Subresource Integrity (SRI) attribute")

        risk = "low" if not has_sri else "info"

        resources.append(ThirdPartyResource(
            url=url,
            resource_type="stylesheet",
            provider=provider,
            has_sri=has_sri,
            risk=risk,
            issues=issues_ss,
        ))

    # Overall risk
    risks = [r.risk for r in resources]
    if "high" in risks:
        risk_summary = "high"
    elif "medium" in risks:
        risk_summary = "medium"
    elif "low" in risks:
        risk_summary = "low"
    else:
        risk_summary = "none"

    # Top-level issues
    top_issues: list[str] = []
    if vuln_count:
        top_issues.append(f"{vuln_count} known vulnerable library version(s) detected")
    compromised = [r for r in resources if "COMPROMISED" in r.provider]
    if compromised:
        top_issues.append(f"Resources loaded from compromised provider: {compromised[0].provider}")
    if scripts_no_sri:
        top_issues.append(f"{scripts_no_sri} external script(s) without Subresource Integrity")

    return SupplyChainResult(
        total_external_resources=len(resources),
        scripts_without_sri=scripts_no_sri,
        stylesheets_without_sri=stylesheets_no_sri,
        vulnerable_libraries=vuln_count,
        providers=sorted(providers_set),
        resources=resources,
        risk_summary=risk_summary,
        issues=top_issues,
    )


__all__ = ["analyze_supply_chain"]
