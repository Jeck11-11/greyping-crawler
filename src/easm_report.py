"""EASM (External Attack Surface Management) report builder.

Post-processes a populated ``DomainResult`` into a business-grade report
with classified findings, ownership tagging, condensed summaries, and a
deterministic executive summary. Follows the same pattern as
``fair_signals.py`` — a pure function, no I/O, no scanner changes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .models import (
    AssetContext,
    CertificateSummary,
    CloudAsset,
    CookieSummary,
    DNSPostureSummary,
    DomainResult,
    EASMReport,
    ExecutiveSummary,
    FindingClassification,
    FindingOwner,
    JSIntelSummary,
    PageSummary,
    PrioritizedFinding,
    ReconArtifact,
    SourcemapSummary,
    TechSummary,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Platform profiles — which cookies/headers are platform-managed
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PlatformProfile:
    known_cookies: frozenset[str] = field(default_factory=frozenset)
    managed_headers: frozenset[str] = field(default_factory=frozenset)
    owns_infrastructure: bool = True


_PLATFORM_PROFILES: dict[str, PlatformProfile] = {
    "Wix": PlatformProfile(
        known_cookies=frozenset({"XSRF-TOKEN", "hs", "svSession", "ssr-caching"}),
        managed_headers=frozenset({
            "content-security-policy", "strict-transport-security",
            "permissions-policy", "x-frame-options",
        }),
    ),
    "Shopify": PlatformProfile(
        known_cookies=frozenset({"_shopify_s", "_shopify_y", "cart_sig", "secure_customer_sig"}),
        managed_headers=frozenset({"content-security-policy"}),
    ),
    "Squarespace": PlatformProfile(
        known_cookies=frozenset({"ss_cid", "ss_cpvisit", "ss_cvr"}),
        managed_headers=frozenset({
            "content-security-policy", "strict-transport-security",
        }),
    ),
    "Webflow": PlatformProfile(
        known_cookies=frozenset(set()),
        managed_headers=frozenset({
            "content-security-policy", "strict-transport-security",
        }),
    ),
    "WordPress.com": PlatformProfile(
        known_cookies=frozenset({"wordpress_logged_in", "wp-settings"}),
        managed_headers=frozenset({"content-security-policy"}),
    ),
    "Vercel": PlatformProfile(
        known_cookies=frozenset(set()),
        managed_headers=frozenset(set()),
        owns_infrastructure=True,
    ),
    "Netlify": PlatformProfile(
        known_cookies=frozenset(set()),
        managed_headers=frozenset(set()),
        owns_infrastructure=True,
    ),
    "GitHub Pages": PlatformProfile(
        known_cookies=frozenset(set()),
        managed_headers=frozenset({
            "content-security-policy", "permissions-policy",
        }),
    ),
}

_NO_PLATFORM = PlatformProfile(
    known_cookies=frozenset(), managed_headers=frozenset(), owns_infrastructure=False,
)


def _detect_primary_platform(result: DomainResult) -> tuple[str, PlatformProfile]:
    """Identify the hosting platform from tech fingerprint + passive intel."""
    for tech in result.technologies:
        if tech.confidence == "low":
            continue
        name = tech.name
        if name in _PLATFORM_PROFILES:
            return name, _PLATFORM_PROFILES[name]
        for pname in _PLATFORM_PROFILES:
            if pname.lower() in name.lower():
                return pname, _PLATFORM_PROFILES[pname]

    if result.passive_intel and result.passive_intel.ip_enrichment:
        for provider in result.passive_intel.ip_enrichment.hosting_providers:
            if provider in _PLATFORM_PROFILES:
                return provider, _PLATFORM_PROFILES[provider]

    return "", _NO_PLATFORM


# ---------------------------------------------------------------------------
# Sort helpers
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CLASSIFICATION_ORDER = {
    "confirmed_issue": 0, "platform_behavior": 2,
    "informational": 3, "false_positive_likely": 4,
}
_CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}
_OWNER_ORDER = {"customer": 0, "third_party": 1, "platform": 2, "not_actionable": 3}


def _sort_findings(findings: list[PrioritizedFinding]) -> list[PrioritizedFinding]:
    return sorted(findings, key=lambda f: (
        _SEVERITY_ORDER.get(f.severity, 5),
        _CLASSIFICATION_ORDER.get(f.classification.value, 5),
        _CONFIDENCE_ORDER.get(f.confidence, 5),
        _OWNER_ORDER.get(f.owner.value, 5),
    ))


# ---------------------------------------------------------------------------
# Classifiers — one per finding source
# ---------------------------------------------------------------------------

def _classify_header_findings(
    result: DomainResult, platform: str, profile: PlatformProfile,
) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    headers = result.security_headers
    if not headers or (not headers.grade and not headers.findings):
        return findings

    for h in headers.findings:
        if h.status == "missing":
            hdr_lower = h.header.lower()
            if hdr_lower in profile.managed_headers:
                findings.append(PrioritizedFinding(
                    id=f"missing_{hdr_lower.replace('-', '_')}",
                    title=f"Missing {h.header}",
                    category="security_headers",
                    severity=h.severity,
                    classification=FindingClassification.platform_behavior,
                    confidence="high",
                    owner=FindingOwner.platform,
                    platform_name=platform,
                    why_it_matters=f"This header is managed by {platform} and cannot be configured by the site owner.",
                    business_impact="Limited — platform-controlled",
                    evidence=[f"{h.header} not present in response"],
                    recommended_action=f"Contact {platform} support or migrate to a platform that allows custom headers.",
                    source_field="security_headers",
                ))
            else:
                findings.append(PrioritizedFinding(
                    id=f"missing_{hdr_lower.replace('-', '_')}",
                    title=f"Missing {h.header}",
                    category="security_headers",
                    severity=h.severity,
                    classification=FindingClassification.confirmed_issue,
                    confidence="high",
                    owner=FindingOwner.customer,
                    why_it_matters=h.recommendation or f"Missing {h.header} weakens browser-side protections.",
                    business_impact="Web security hygiene",
                    evidence=[f"{h.header} not present in response"],
                    recommended_action=h.recommendation or f"Add {h.header} header to server configuration.",
                    source_field="security_headers",
                ))
        elif h.status == "present" and h.header.lower() in ("server", "x-powered-by"):
            findings.append(PrioritizedFinding(
                id=f"info_leak_{h.header.lower().replace('-', '_')}",
                title=f"Information leakage via {h.header}",
                category="security_headers",
                severity="info",
                classification=FindingClassification.informational,
                confidence="high",
                owner=FindingOwner.customer,
                why_it_matters="Reveals server software, aiding attacker reconnaissance.",
                business_impact="Minimal — aids targeted attacks",
                evidence=[f"{h.header}: {h.value}"],
                recommended_action=f"Remove or obscure the {h.header} header.",
                source_field="security_headers",
            ))
    return findings


def _classify_cookie_findings(
    result: DomainResult, platform: str, profile: PlatformProfile,
) -> tuple[list[PrioritizedFinding], CookieSummary]:
    findings: list[PrioritizedFinding] = []
    summary = CookieSummary(total=len(result.cookies))

    for cookie in result.cookies:
        if not cookie.issues:
            continue
        summary.with_issues += 1

        is_platform = cookie.name in profile.known_cookies
        is_xsrf = cookie.name.upper().startswith("XSRF")

        if is_platform or is_xsrf:
            summary.platform_standard += 1
            findings.append(PrioritizedFinding(
                id=f"cookie_{cookie.name}",
                title=f"Cookie '{cookie.name}' has issues",
                category="cookies",
                severity="info",
                classification=FindingClassification.platform_behavior,
                confidence="high",
                owner=FindingOwner.platform,
                platform_name=platform or "framework",
                why_it_matters="Expected behavior for this platform/framework; not customer-configurable." if is_platform
                    else "XSRF tokens are intentionally readable by JavaScript for CSRF protection.",
                business_impact="None — by design",
                evidence=[f"{cookie.name}: {', '.join(cookie.issues)}"],
                recommended_action="No action required.",
                source_field="cookies",
            ))
        else:
            summary.customer_actionable += 1
            summary.notable.append(cookie.name)
            findings.append(PrioritizedFinding(
                id=f"cookie_{cookie.name}",
                title=f"Insecure cookie '{cookie.name}'",
                category="cookies",
                severity=cookie.severity,
                classification=FindingClassification.confirmed_issue,
                confidence="high",
                owner=FindingOwner.customer,
                why_it_matters="Session or auth cookies without proper flags can be stolen via XSS or MITM.",
                business_impact="Session hijacking risk",
                evidence=[f"{cookie.name}: {', '.join(cookie.issues)}"],
                recommended_action="Set Secure, HttpOnly, and SameSite=Lax/Strict flags.",
                source_field="cookies",
            ))
    return findings, summary


def _classify_ssl_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    ssl = result.ssl_certificate
    if not ssl or (not ssl.grade and not ssl.issues and ssl.is_valid):
        return findings

    if not ssl.is_valid:
        findings.append(PrioritizedFinding(
            id="ssl_invalid",
            title="Invalid SSL/TLS certificate",
            category="ssl",
            severity="critical",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Browsers will show security warnings, blocking visitors and destroying trust.",
            business_impact="Service disruption, brand damage",
            evidence=ssl.issues[:3] or ["Certificate failed validation"],
            recommended_action="Renew or replace the SSL certificate immediately.",
            source_field="ssl_certificate",
        ))
    elif ssl.days_until_expiry and 0 < ssl.days_until_expiry <= 30:
        findings.append(PrioritizedFinding(
            id="ssl_expiring_soon",
            title=f"SSL certificate expires in {ssl.days_until_expiry} days",
            category="ssl",
            severity="high",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="An expired certificate will trigger browser warnings and break HTTPS.",
            business_impact="Imminent service disruption",
            evidence=[f"Expires: {ssl.not_after}, {ssl.days_until_expiry} days remaining"],
            recommended_action="Renew the certificate before expiry. Enable auto-renewal if possible.",
            source_field="ssl_certificate",
        ))
    return findings


def _classify_secret_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    for s in result.secrets:
        is_generic = "generic" in s.matched_pattern.lower()
        findings.append(PrioritizedFinding(
            id=f"secret_{s.secret_type}",
            title=f"Exposed {s.secret_type}",
            category="secrets",
            severity=s.severity,
            classification=FindingClassification.confirmed_issue,
            confidence="medium" if is_generic else "high",
            owner=FindingOwner.customer,
            why_it_matters="Exposed credentials can be used by attackers to access systems or data.",
            business_impact="Data breach risk, unauthorized access",
            evidence=[f"{s.secret_type} found in {s.location}: {s.value_preview}"],
            recommended_action="Rotate the credential immediately and remove it from source code.",
            source_field="secrets",
        ))
    return findings


def _classify_path_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    for p in result.sensitive_paths:
        if p.severity == "info":
            continue
        if p.status_code == 403:
            findings.append(PrioritizedFinding(
                id=f"path_{p.path.strip('/').replace('/', '_').replace('.', '_')}",
                title=f"Path {p.path} exists (403 Forbidden)",
                category="sensitive_paths",
                severity="info",
                classification=FindingClassification.informational,
                confidence="low",
                owner=FindingOwner.customer,
                why_it_matters="Path exists but is access-restricted. Confirms infrastructure detail.",
                business_impact="Minimal — access denied",
                evidence=[f"{p.url} → {p.status_code}"],
                recommended_action="Verify access controls are intentional. Consider returning 404 instead.",
                source_field="sensitive_paths",
            ))
        elif p.status_code == 200:
            findings.append(PrioritizedFinding(
                id=f"path_{p.path.strip('/').replace('/', '_').replace('.', '_')}",
                title=f"Exposed sensitive path: {p.path}",
                category="sensitive_paths",
                severity=p.severity,
                classification=FindingClassification.confirmed_issue,
                confidence="high",
                owner=FindingOwner.customer,
                why_it_matters=p.risk or "Sensitive file or directory is publicly accessible.",
                business_impact="Data exposure, credential leakage",
                evidence=[f"{p.url} → {p.status_code} ({p.content_length} bytes)"],
                recommended_action="Remove or restrict access to this path immediately.",
                source_field="sensitive_paths",
            ))
    return findings


def _classify_ioc_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    for ioc in result.ioc_findings:
        is_heuristic = ioc.ioc_type == "suspicious_script" and ioc.severity == "medium"
        findings.append(PrioritizedFinding(
            id=f"ioc_{ioc.ioc_type}",
            title=f"IoC detected: {ioc.ioc_type.replace('_', ' ').title()}",
            category="ioc",
            severity=ioc.severity,
            classification=FindingClassification.informational if is_heuristic
                else FindingClassification.confirmed_issue,
            confidence="low" if is_heuristic else "high",
            owner=FindingOwner.customer,
            why_it_matters=ioc.description,
            business_impact="Active compromise indicator" if not is_heuristic else "Requires manual verification",
            evidence=[ioc.evidence] if ioc.evidence else [ioc.description],
            recommended_action="Investigate immediately and engage incident response." if not is_heuristic
                else "Review the flagged script manually to determine if it is malicious.",
            source_field="ioc_findings",
        ))
    return findings


def _classify_email_security(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    if not result.passive_intel or not result.passive_intel.email_security:
        return findings
    es = result.passive_intel.email_security
    if es.error:
        return findings

    if not es.spf.exists:
        findings.append(PrioritizedFinding(
            id="email_no_spf",
            title="No SPF record configured",
            category="email_security",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Without SPF, anyone can send email appearing to come from this domain.",
            business_impact="Phishing and brand impersonation risk",
            evidence=["No SPF TXT record found for domain"],
            recommended_action="Add an SPF TXT record to DNS (e.g., v=spf1 include:_spf.google.com -all).",
            source_field="passive_intel.email_security",
        ))
    elif es.spf.all_qualifier in ("+all", "?all"):
        findings.append(PrioritizedFinding(
            id="email_weak_spf",
            title=f"SPF uses weak qualifier: {es.spf.all_qualifier}",
            category="email_security",
            severity="high",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters=f"SPF {es.spf.all_qualifier} allows any server to send as this domain.",
            business_impact="Phishing and brand impersonation risk",
            evidence=[f"SPF record: {es.spf.raw}"],
            recommended_action="Change the SPF qualifier to -all (hard fail) or ~all (soft fail).",
            source_field="passive_intel.email_security",
        ))

    if not es.dmarc.exists:
        findings.append(PrioritizedFinding(
            id="email_no_dmarc",
            title="No DMARC record configured",
            category="email_security",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Without DMARC, email spoofing of this domain is trivial and undetectable.",
            business_impact="Phishing, brand impersonation, BEC risk",
            evidence=["No _dmarc TXT record found"],
            recommended_action="Add a DMARC record (e.g., v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com).",
            source_field="passive_intel.email_security",
        ))
    elif es.dmarc.policy == "none":
        findings.append(PrioritizedFinding(
            id="email_dmarc_none",
            title="DMARC policy is 'none' (monitoring only)",
            category="email_security",
            severity="low",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="DMARC p=none provides visibility but does not block spoofed email.",
            business_impact="Acceptable as an interim step toward enforcement",
            evidence=[f"DMARC record: {es.dmarc.raw}"],
            recommended_action="Upgrade to p=quarantine or p=reject once monitoring shows clean traffic.",
            source_field="passive_intel.email_security",
        ))

    if not es.dkim.selectors_found:
        findings.append(PrioritizedFinding(
            id="email_no_dkim",
            title="No DKIM selectors found",
            category="email_security",
            severity="low",
            classification=FindingClassification.informational,
            confidence="low",
            owner=FindingOwner.customer,
            why_it_matters="DKIM provides cryptographic proof of email authenticity.",
            business_impact="Email deliverability and anti-spoofing",
            evidence=[f"Checked {len(es.dkim.selectors_checked)} common selectors, none found"],
            recommended_action="Verify DKIM is configured with your email provider. Non-standard selectors may exist.",
            source_field="passive_intel.email_security",
        ))
    return findings


def _classify_dns_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    if not result.passive_intel or not result.passive_intel.dns:
        return findings
    dns = result.passive_intel.dns
    if dns.error:
        return findings

    if dns.dnssec is False:
        findings.append(PrioritizedFinding(
            id="dns_no_dnssec",
            title="DNSSEC not enabled",
            category="dns",
            severity="low",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Without DNSSEC, DNS responses can be spoofed via cache poisoning.",
            business_impact="DNS hijacking risk (requires targeted attack)",
            evidence=["No DNSKEY record found for domain"],
            recommended_action="Enable DNSSEC with your DNS provider / registrar.",
            source_field="passive_intel.dns",
        ))

    if not dns.caa_records:
        findings.append(PrioritizedFinding(
            id="dns_no_caa",
            title="No CAA records — any CA can issue certificates",
            category="dns",
            severity="low",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Without CAA, any Certificate Authority can issue certs for this domain.",
            business_impact="Reduces defense against mis-issuance",
            evidence=["No CAA DNS record found"],
            recommended_action="Add CAA records to restrict certificate issuance to your preferred CA.",
            source_field="passive_intel.dns",
        ))

    if not dns.aaaa_records:
        findings.append(PrioritizedFinding(
            id="dns_no_ipv6",
            title="No IPv6 (AAAA) records",
            category="dns",
            severity="info",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="IPv6 connectivity is increasingly expected for modern web presence.",
            business_impact="Accessibility gap for IPv6-only networks",
            evidence=["No AAAA records resolved"],
            recommended_action="Consider adding AAAA records if your hosting supports IPv6.",
            source_field="passive_intel.dns",
        ))

    return findings


def _classify_breach_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    for b in result.breaches:
        findings.append(PrioritizedFinding(
            id=f"breach_{b.breach_name or b.source}".lower().replace(" ", "_"),
            title=f"Historical breach: {b.breach_name or b.source}",
            category="breaches",
            severity="high",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.not_actionable,
            why_it_matters=f"Data exposed in this breach may still be exploitable (types: {', '.join(b.data_types[:3])}).",
            business_impact="Credential stuffing, account takeover, regulatory exposure",
            evidence=[f"{b.breach_name or b.source} ({b.breach_date}): {', '.join(b.data_types[:5])}"],
            recommended_action="Ensure affected users have reset passwords. Monitor for credential reuse.",
            source_field="breaches",
        ))
    return findings


# ---------------------------------------------------------------------------
# JS intel condensation + classification
# ---------------------------------------------------------------------------

_VENDOR_PREFIXES = (
    "node_modules/", "webpack/", "react/", "vue/", "angular/",
    "@babel/", "@emotion/", "@mui/", "lodash/", "core-js/",
    "regenerator-runtime/", "tslib/", "rxjs/",
)


def _classify_js_intel(result: DomainResult) -> tuple[list[PrioritizedFinding], JSIntelSummary | None]:
    findings: list[PrioritizedFinding] = []
    if not result.js_intel:
        return findings, None

    ji = result.js_intel
    vendor_count = 0
    first_party_count = 0
    for f in ji.recovered_source_files:
        if any(f.startswith(p) or f"/{p}" in f for p in _VENDOR_PREFIXES):
            vendor_count += 1
        else:
            first_party_count += 1

    if vendor_count and first_party_count:
        ownership = "mixed"
    elif first_party_count:
        ownership = "first_party"
    elif vendor_count:
        ownership = "vendor"
    else:
        ownership = "unknown"

    if first_party_count > 10:
        prop_exposure = "high"
    elif first_party_count > 0:
        prop_exposure = "low"
    else:
        prop_exposure = "none"

    sm_summary = SourcemapSummary(
        detected=bool(ji.sourcemaps_found),
        count=len(ji.sourcemaps_found),
        ownership=ownership,
        proprietary_exposure=prop_exposure,
    )

    notable = [e for e in ji.api_endpoints if e.startswith("/api")][:5]

    summary = JSIntelSummary(
        scripts_scanned=ji.scripts_scanned,
        api_endpoints_count=len(ji.api_endpoints),
        internal_hosts_count=len(ji.internal_hosts),
        sourcemaps=sm_summary,
        notable_endpoints=notable,
    )

    if ji.internal_hosts:
        findings.append(PrioritizedFinding(
            id="js_internal_hosts",
            title=f"Internal hostnames exposed in JavaScript ({len(ji.internal_hosts)})",
            category="js_intel",
            severity="high",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Internal hostnames reveal private infrastructure to attackers.",
            business_impact="Network reconnaissance aid",
            evidence=ji.internal_hosts[:3],
            recommended_action="Remove internal hostnames from production JavaScript bundles.",
            source_field="js_intel",
        ))

    if prop_exposure == "high":
        findings.append(PrioritizedFinding(
            id="js_sourcemap_exposure",
            title="Proprietary source code exposed via sourcemaps",
            category="js_intel",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="medium",
            owner=FindingOwner.customer,
            why_it_matters="Attackers can read application logic to find vulnerabilities.",
            business_impact="Intellectual property exposure, vulnerability discovery",
            evidence=[f"{first_party_count} first-party source files recoverable"],
            recommended_action="Disable sourcemap generation in production builds.",
            source_field="js_intel",
        ))
    elif sm_summary.detected and ownership == "vendor":
        findings.append(PrioritizedFinding(
            id="js_sourcemap_vendor",
            title="Sourcemaps detected (vendor/framework only)",
            category="js_intel",
            severity="info",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.not_actionable,
            why_it_matters="Only third-party framework sourcemaps detected — no proprietary code exposed.",
            business_impact="None",
            evidence=[f"{vendor_count} vendor source files from framework dependencies"],
            recommended_action="No action required.",
            source_field="js_intel",
        ))

    return findings, summary


# ---------------------------------------------------------------------------
# Tech summary condensation
# ---------------------------------------------------------------------------

def _build_tech_summary(result: DomainResult, platform: str) -> TechSummary | None:
    if not result.technologies:
        return None
    high = [t.name for t in result.technologies if t.confidence == "high"]
    other = sum(1 for t in result.technologies if t.confidence != "high")
    return TechSummary(platform=platform, high_confidence=high, other_count=other)


# ---------------------------------------------------------------------------
# Asset context inference
# ---------------------------------------------------------------------------

_STAGING_INDICATORS = ("staging", "stage", "dev", "test", "qa", "uat", "preview", "sandbox", "beta")
_APP_CATEGORIES = frozenset({"webmail", "vpn", "remote_access", "database"})
_ECOMMERCE_NAMES = frozenset({"Shopify", "WooCommerce", "Magento", "BigCommerce", "PrestaShop"})


def _infer_asset_context(result: DomainResult, platform: str, profile: PlatformProfile) -> AssetContext:
    evidence: list[str] = []
    domain = result.metadata.get("domain", "")

    is_staging = any(ind in domain.lower() for ind in _STAGING_INDICATORS)
    env = "staging" if is_staging else "production"
    if is_staging:
        evidence.append(f"Domain contains staging indicator: {domain}")
    else:
        evidence.append("No staging indicators in domain name")

    tech_names = {t.name for t in result.technologies}
    tech_cats = set()
    for t in result.technologies:
        tech_cats.update(t.categories)

    if tech_cats & _ECOMMERCE_NAMES or any(n in _ECOMMERCE_NAMES for n in tech_names):
        asset_type = "ecommerce"
        evidence.append("Ecommerce platform detected")
    elif tech_cats & _APP_CATEGORIES:
        asset_type = "web_app"
        evidence.append(f"Application-type tech detected: {tech_cats & _APP_CATEGORIES}")
    elif result.js_intel and len(result.js_intel.api_endpoints) > 5:
        asset_type = "web_app"
        evidence.append(f"{len(result.js_intel.api_endpoints)} API endpoints suggest a web application")
    elif platform in ("Wix", "Squarespace", "Webflow"):
        asset_type = "brochure_site"
        evidence.append(f"Built on {platform} — typically a brochure/marketing site")
    elif result.pages_scanned == 0 and not result.technologies:
        asset_type = "unknown"
    else:
        asset_type = "website"
        evidence.append("General website")

    if profile.owns_infrastructure:
        hosting = "managed_platform"
        evidence.append(f"Fully managed on {platform}")
    elif result.passive_intel and result.passive_intel.ip_enrichment:
        providers = result.passive_intel.ip_enrichment.hosting_providers
        if providers:
            hosting = "cloud_hosted"
            evidence.append(f"Hosted on {', '.join(providers[:2])}")
        else:
            hosting = "self_hosted"
            evidence.append("No major cloud provider detected in ASN")
    else:
        hosting = "unknown"

    if asset_type == "ecommerce":
        criticality = "high"
    elif asset_type == "web_app":
        criticality = "high"
    elif is_staging:
        criticality = "low"
    elif asset_type == "brochure_site":
        criticality = "medium"
    else:
        criticality = "medium"

    return AssetContext(
        asset_type=asset_type,
        environment=env,
        audience="customer_facing",
        hosting_type=hosting,
        business_criticality=criticality,
        inferred_from=evidence,
    )


# ---------------------------------------------------------------------------
# DNS posture summary
# ---------------------------------------------------------------------------

def _build_dns_posture(result: DomainResult) -> DNSPostureSummary | None:
    if not result.passive_intel:
        return None
    dns = result.passive_intel.dns
    es = result.passive_intel.email_security
    ip_enrich = result.passive_intel.ip_enrichment
    if not dns and not es:
        return None

    summary = DNSPostureSummary()
    if dns and not dns.error:
        summary.a_records = [r.address for r in dns.a_records]
        summary.aaaa_records = [r.address for r in dns.aaaa_records]
        summary.a_record_count = len(dns.a_records)
        summary.has_ipv6 = bool(dns.aaaa_records)
        summary.nameservers = [ns.host for ns in dns.ns_records[:5]] if dns.ns_records else ["not_found"]
        summary.cname_chain = [c.target for c in dns.cname_records]
        summary.txt_records = [t.data for t in dns.txt_records]
        summary.mx_hosts = [f"{mx.priority} {mx.host}" for mx in dns.mx_records]

        if dns.soa_record:
            summary.soa_primary_ns = dns.soa_record.primary_ns
            summary.soa_admin_email = dns.soa_record.admin_email
            summary.soa_serial = dns.soa_record.serial
            summary.soa_refresh = dns.soa_record.refresh
            summary.soa_retry = dns.soa_record.retry
            summary.soa_expire = dns.soa_record.expire
            summary.soa_minimum_ttl = dns.soa_record.minimum_ttl
        else:
            summary.soa_primary_ns = "not_found"
            summary.soa_admin_email = "not_found"

        if dns.srv_records:
            summary.srv_services = sorted({r.service for r in dns.srv_records})
        else:
            summary.srv_services = ["not_found"]

        if dns.caa_records:
            summary.caa_records = dns.caa_records
            summary.caa_restricted = any("issue" in c.lower() for c in dns.caa_records)
        else:
            summary.caa_records = ["not_found"]
            summary.caa_restricted = False

        summary.ptr_records = dns.ptr_records[:10] if dns.ptr_records else ["not_found"]

        if dns.dnssec is True:
            summary.dnssec_enabled = True
        elif dns.dnssec is False:
            summary.dnssec_enabled = False
        else:
            summary.dnssec_enabled = None

    if ip_enrich and not ip_enrich.error:
        summary.ip_asn_map = [
            {
                "ip": r.ip,
                "asn": r.asn,
                "asn_name": r.asn_name,
                "prefix": r.prefix,
                "country_code": r.country_code,
            }
            for r in ip_enrich.records
        ]
        summary.hosting_providers = ip_enrich.hosting_providers or ["not_found"]
        summary.hosting_countries = ip_enrich.countries or ["not_found"]

    if es and not es.error:
        summary.email_grade = es.grade or "not_found"
        summary.mail_providers = es.mail_providers if es.mail_providers else ["not_found"]

        if not es.spf.exists:
            summary.spf_status = "not_found"
        elif es.spf.all_qualifier == "-all":
            summary.spf_status = "pass"
        elif es.spf.all_qualifier == "~all":
            summary.spf_status = "soft_fail"
        else:
            summary.spf_status = "weak"

        if not es.dmarc.exists:
            summary.dmarc_status = "not_found"
        elif es.dmarc.policy in ("reject", "quarantine"):
            summary.dmarc_status = "enforce"
        else:
            summary.dmarc_status = "monitor"

        summary.dkim_status = "found" if es.dkim.selectors_found else "not_found"
    else:
        summary.spf_status = "not_found"
        summary.dmarc_status = "not_found"
        summary.dkim_status = "not_found"
        summary.email_grade = "not_found"
        summary.mail_providers = ["not_found"]

    return summary


# ---------------------------------------------------------------------------
# Certificate summary
# ---------------------------------------------------------------------------

def _build_certificate_summary(result: DomainResult) -> CertificateSummary | None:
    ssl = result.ssl_certificate
    passive = result.passive_intel

    has_ssl = ssl and (ssl.grade or ssl.issuer or ssl.issues)
    has_ct = passive and passive.ct and not passive.ct.error
    if not has_ssl and not has_ct:
        return None

    summary = CertificateSummary()
    if ssl:
        summary.current_valid = ssl.is_valid
        summary.current_issuer = ssl.issuer
        summary.current_grade = ssl.grade
        summary.days_until_expiry = ssl.days_until_expiry
        summary.san_domains = ssl.san[:20]

    if has_ct:
        summary.ct_subdomains = passive.ct.subdomains[:30]
        summary.ct_issuers = passive.ct.issuers[:10]
        summary.certificates_seen = passive.ct.certificates_seen

    return summary


# ---------------------------------------------------------------------------
# Cloud asset / SaaS detection
# ---------------------------------------------------------------------------

import re

_CLOUD_PATTERNS = [
    (re.compile(r"https?://([a-z0-9\-]+)\.s3[.\-]amazonaws\.com", re.I), "s3_bucket"),
    (re.compile(r"https?://s3[.\-]amazonaws\.com/([a-z0-9\-]+)", re.I), "s3_bucket"),
    (re.compile(r"https?://([a-z0-9\-]+)\.blob\.core\.windows\.net", re.I), "azure_blob"),
    (re.compile(r"https?://storage\.googleapis\.com/([a-z0-9\-]+)", re.I), "gcs_bucket"),
    (re.compile(r"https?://([a-z0-9\-]+)\.storage\.googleapis\.com", re.I), "gcs_bucket"),
    (re.compile(r"https?://([a-z0-9\-]+)\.firebaseio\.com", re.I), "firebase"),
    (re.compile(r"https?://([a-z0-9\-]+)\.firebaseapp\.com", re.I), "firebase"),
]

_SAAS_DOMAINS = {
    "intercom.io": "Intercom",
    "zendesk.com": "Zendesk",
    "hubspot.com": "HubSpot",
    "salesforce.com": "Salesforce",
    "mailchimp.com": "Mailchimp",
    "sendgrid.net": "SendGrid",
    "slack.com": "Slack",
    "atlassian.net": "Atlassian",
    "freshdesk.com": "Freshdesk",
    "drift.com": "Drift",
    "crisp.chat": "Crisp",
    "tawk.to": "Tawk.to",
}


def _detect_cloud_assets(result: DomainResult) -> list[CloudAsset]:
    assets: list[CloudAsset] = []
    seen: set[str] = set()

    all_urls: list[tuple[str, str]] = []
    for link in result.external_links:
        all_urls.append((link.url, "html"))
    if result.js_intel:
        for ep in result.js_intel.api_endpoints:
            all_urls.append((ep, "js"))
    for page in result.pages:
        for link in page.links:
            if link.link_type == "external":
                all_urls.append((link.url, "html"))

    for url, source in all_urls:
        for pattern, asset_type in _CLOUD_PATTERNS:
            m = pattern.search(url)
            if m:
                identifier = m.group(1)
                key = f"{asset_type}:{identifier}"
                if key not in seen:
                    seen.add(key)
                    assets.append(CloudAsset(asset_type=asset_type, identifier=identifier, source=source))

        try:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            for domain_pat, saas_name in _SAAS_DOMAINS.items():
                if host.endswith(domain_pat):
                    key = f"saas:{saas_name}"
                    if key not in seen:
                        seen.add(key)
                        assets.append(CloudAsset(asset_type="saas_platform", identifier=saas_name, source=source))
                    break
        except Exception:
            pass

    return assets


# ---------------------------------------------------------------------------
# Page summary — condense verbose page data
# ---------------------------------------------------------------------------

def _build_page_summary(result: DomainResult) -> PageSummary | None:
    if not result.pages:
        return None

    from urllib.parse import urlparse
    routes: set[str] = set()
    notable: list[str] = []
    ext_domains: dict[str, int] = {}

    for page in result.pages:
        parsed = urlparse(page.url)
        path = parsed.path.rstrip("/") or "/"
        routes.add(path)
        if page.secrets or page.ioc_findings:
            notable.append(page.url)

    for link in result.external_links:
        try:
            host = urlparse(link.url).hostname or ""
            host = host.lower().lstrip("www.")
            if host:
                ext_domains[host] = ext_domains.get(host, 0) + 1
        except Exception:
            pass

    top_ext = sorted(ext_domains, key=ext_domains.get, reverse=True)[:10]

    return PageSummary(
        total_pages=len(result.pages),
        unique_routes=sorted(routes),
        notable_pages=notable[:10],
        unique_emails=len(result.emails),
        unique_phones=len(result.phone_numbers),
        unique_socials=len(result.social_profiles),
        external_dependencies=top_ext,
    )


# ---------------------------------------------------------------------------
# Recon artifacts — reclassify robots.txt, sitemap.xml, etc.
# ---------------------------------------------------------------------------

_RECON_ARTIFACT_PATHS = frozenset({"/robots.txt", "/sitemap.xml", "/security.txt", "/humans.txt"})


def _extract_recon_artifacts(result: DomainResult) -> list[ReconArtifact]:
    artifacts: list[ReconArtifact] = []
    for p in result.sensitive_paths:
        if p.path in _RECON_ARTIFACT_PATHS or p.severity == "info":
            note = "Standard web artifact" if p.path in _RECON_ARTIFACT_PATHS else p.risk or ""
            artifacts.append(ReconArtifact(path=p.path, status_code=p.status_code, note=note))
    return artifacts


# ---------------------------------------------------------------------------
# Executive summary — template-driven, deterministic
# ---------------------------------------------------------------------------

_CONFIDENCE_LABEL = {
    "passive": "low",
    "lighttouch": "medium",
    "full": "high",
    "standard": "high",
}


def _build_executive_summary(
    findings: list[PrioritizedFinding],
    result: DomainResult,
    platform: str,
    scan_mode: str,
) -> ExecutiveSummary:
    confirmed = [f for f in findings if f.classification == FindingClassification.confirmed_issue]
    critical_high = [f for f in confirmed if f.severity in ("critical", "high")]

    if any(f.severity == "critical" for f in confirmed):
        risk_posture = "High"
    elif len(critical_high) >= 3:
        risk_posture = "High"
    elif critical_high:
        risk_posture = "Moderate"
    elif confirmed:
        risk_posture = "Low"
    else:
        risk_posture = "Low"

    fair = result.fair_signals
    if fair and fair.risk_tier == "critical":
        risk_posture = "Critical"
    elif fair and fair.risk_tier == "high" and risk_posture != "Critical":
        risk_posture = "High"

    parts: list[str] = []
    parts.append(f"{risk_posture} overall external risk posture.")

    if any(f.category == "secrets" for f in confirmed):
        secret_count = sum(1 for f in confirmed if f.category == "secrets")
        parts.append(f"Exposed credentials ({secret_count} finding{'s' if secret_count != 1 else ''}) represent the most urgent risk.")
    elif any(f.category == "ioc" for f in confirmed):
        parts.append("Active indicators of compromise detected, suggesting potential ongoing threat.")
    elif any(f.category == "ssl" and f.severity == "critical" for f in confirmed):
        parts.append("Invalid SSL certificate is actively blocking secure connections.")
    elif critical_high:
        top = critical_high[0]
        parts.append(f"Primary concern: {top.title.lower()}.")
    elif confirmed:
        parts.append("Main exposure consists of standard web hygiene gaps.")
    else:
        parts.append("No evidence of leaked secrets, active compromise, or breach exposure.")

    if platform:
        managed = _PLATFORM_PROFILES.get(platform, _NO_PLATFORM).managed_headers
        if managed:
            hdr_list = ", ".join(sorted(managed)[:3])
            parts.append(f"Site runs on {platform}, which manages {hdr_list}; these are not customer-configurable.")
        else:
            parts.append(f"Site runs on {platform}.")

    confidence = _CONFIDENCE_LABEL.get(scan_mode, "low")
    parts.append(f"Based on a {scan_mode} scan with {confidence} confidence.")

    positives: list[str] = []
    if not any(f.category == "secrets" for f in findings):
        positives.append("No exposed secrets or credentials detected")
    if not result.breaches:
        positives.append("No breach history found")
    ssl = result.ssl_certificate
    if ssl and ssl.is_valid and ssl.grade in ("A+", "A", "A-", "B+", "B"):
        positives.append(f"SSL/TLS certificate is valid (grade {ssl.grade})")
    es = result.passive_intel.email_security if result.passive_intel else None
    if es and not es.error and es.dmarc.exists and es.dmarc.policy in ("reject", "quarantine"):
        positives.append(f"DMARC enforcement active (p={es.dmarc.policy})")
    waf_names = [t.name for t in result.technologies if t.name in (
        "Cloudflare", "AWS CloudFront", "Fastly", "Akamai", "Imperva", "Sucuri",
    )]
    if waf_names:
        positives.append(f"WAF/CDN detected: {waf_names[0]}")

    concerns = [f.title for f in critical_high[:3]]

    return ExecutiveSummary(
        risk_posture=risk_posture,
        narrative=" ".join(parts),
        key_positives=positives[:3],
        key_concerns=concerns,
        scan_coverage=scan_mode,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def build_easm_report(
    result: DomainResult, *, scan_mode: str = "full",
) -> EASMReport:
    """Build a business-grade EASM report from a populated DomainResult."""
    try:
        platform, profile = _detect_primary_platform(result)

        all_findings: list[PrioritizedFinding] = []
        all_findings.extend(_classify_header_findings(result, platform, profile))
        cookie_findings, cookie_summary = _classify_cookie_findings(result, platform, profile)
        all_findings.extend(cookie_findings)
        all_findings.extend(_classify_ssl_findings(result))
        all_findings.extend(_classify_secret_findings(result))
        all_findings.extend(_classify_path_findings(result))
        all_findings.extend(_classify_ioc_findings(result))
        all_findings.extend(_classify_email_security(result))
        all_findings.extend(_classify_dns_findings(result))
        all_findings.extend(_classify_breach_findings(result))
        js_findings, js_summary = _classify_js_intel(result)
        all_findings.extend(js_findings)

        sorted_findings = _sort_findings(all_findings)
        tech_summary = _build_tech_summary(result, platform)
        asset_context = _infer_asset_context(result, platform, profile)
        dns_posture = _build_dns_posture(result)
        cert_summary = _build_certificate_summary(result)
        cloud_assets = _detect_cloud_assets(result)
        page_summary = _build_page_summary(result)
        recon_artifacts = _extract_recon_artifacts(result)
        executive = _build_executive_summary(sorted_findings, result, platform, scan_mode)

        confirmed = sum(1 for f in sorted_findings if f.classification == FindingClassification.confirmed_issue)
        plat_beh = sum(1 for f in sorted_findings if f.classification == FindingClassification.platform_behavior)
        info_ct = sum(1 for f in sorted_findings if f.classification == FindingClassification.informational)

        return EASMReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            scan_mode=scan_mode,
            executive_summary=executive,
            asset_context=asset_context,
            dns_posture=dns_posture,
            certificate_summary=cert_summary,
            cloud_assets=cloud_assets,
            page_summary=page_summary,
            recon_artifacts=recon_artifacts,
            prioritized_findings=sorted_findings,
            total_findings=len(sorted_findings),
            confirmed_issues=confirmed,
            platform_behaviors=plat_beh,
            informational_count=info_ct,
            js_intel_summary=js_summary,
            cookie_summary=cookie_summary if cookie_summary.total else None,
            tech_summary=tech_summary,
            platform_detected=platform,
        )
    except Exception as exc:
        logger.warning("EASM report generation failed for %s: %s", result.target, exc)
        return EASMReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            scan_mode=scan_mode,
        )


__all__ = ["build_easm_report"]
