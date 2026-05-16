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
    CloudAsset,
    ComplianceControl,
    CompliancePosture,
    DomainResult,
    EASMReport,
    ExecutiveSummary,
    FinancialImpact,
    FindingClassification,
    FindingOwner,
    PrioritizedFinding,
    RansomwareIndex,
    ReconArtifact,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compliance framework mapping — finding ID → applicable references
# ---------------------------------------------------------------------------
# Keys are the stable ``id`` values set on ``PrioritizedFinding`` objects in
# the classifier functions below.  Values list the relevant PCI-DSS, GDPR
# and ISO 27001 controls.  For *dynamic* IDs (e.g. ``secret_*``,
# ``ioc_*``, ``breach_*``), a prefix-based lookup is used at application
# time so we don't need to enumerate every possible suffix.

_COMPLIANCE_MAP: dict[str, list[str]] = {
    # -- Security headers --------------------------------------------------
    "missing_strict_transport_security": [
        "PCI-DSS 4.1",
        "ISO 27001 A.14.1.2",
    ],
    "missing_content_security_policy": [
        "PCI-DSS 6.5.7",
        "ISO 27001 A.14.1.2",
    ],
    "missing_x_frame_options": [
        "PCI-DSS 6.5.7",
        "ISO 27001 A.14.1.2",
    ],
    "missing_x_content_type_options": [
        "PCI-DSS 6.5.x",
        "ISO 27001 A.14.1.2",
    ],
    "missing_referrer_policy": [
        "ISO 27001 A.14.1.2",
    ],
    "missing_permissions_policy": [
        "ISO 27001 A.14.1.2",
    ],
    "info_leak_server": [
        "PCI-DSS 6.5.5",
        "ISO 27001 A.12.6.1",
    ],
    "info_leak_x_powered_by": [
        "PCI-DSS 6.5.5",
        "ISO 27001 A.12.6.1",
    ],
    # -- SSL / TLS ---------------------------------------------------------
    "ssl_invalid": [
        "PCI-DSS 4.1",
        "ISO 27001 A.10.1.1",
    ],
    "ssl_expiring_soon": [
        "PCI-DSS 4.1",
        "ISO 27001 A.10.1.1",
    ],
    "ssl_weak_cipher": [
        "PCI-DSS 4.1",
        "ISO 27001 A.10.1.1",
    ],
    "ssl_no_pfs": [
        "PCI-DSS 4.1",
        "ISO 27001 A.10.1.1",
    ],
    "ssl_weak_key": [
        "PCI-DSS 4.1",
        "ISO 27001 A.10.1.1",
    ],
    "ssl_no_sct": [
        "ISO 27001 A.10.1.1",
    ],
    # -- Supply chain ------------------------------------------------------
    "supply_chain_vulnerable_lib": [
        "PCI-DSS 6.2",
        "ISO 27001 A.12.6.1",
    ],
    "supply_chain_no_sri": [
        "PCI-DSS 6.5.7",
        "ISO 27001 A.14.1.2",
    ],
    "supply_chain_compromised_provider": [
        "PCI-DSS 6.2",
        "ISO 27001 A.15.1.1",
    ],
    # -- Email security ----------------------------------------------------
    "email_no_spf": [
        "ISO 27001 A.13.2.1",
    ],
    "email_weak_spf": [
        "ISO 27001 A.13.2.1",
    ],
    "email_no_dmarc": [
        "ISO 27001 A.13.2.1",
    ],
    "email_dmarc_none": [
        "ISO 27001 A.13.2.1",
    ],
    "email_no_dkim": [
        "ISO 27001 A.13.2.1",
    ],
    # -- DNS ---------------------------------------------------------------
    "dns_no_dnssec": [
        "ISO 27001 A.13.1.1",
    ],
    "dns_no_caa": [
        "ISO 27001 A.13.1.1",
    ],
    "dns_no_ipv6": [],
    # -- Robots / Sitemap --------------------------------------------------
    "robots_sensitive_disallow": [
        "PCI-DSS 6.5.8",
    ],
    "sitemap_large_surface": [],
    # -- JS intel ----------------------------------------------------------
    "js_internal_hosts": [
        "ISO 27001 A.13.1.3",
    ],
    "js_sourcemap_exposure": [
        "ISO 27001 A.14.1.2",
    ],
    "js_sourcemap_vendor": [],
    # -- CORS ---------------------------------------------------------------
    "cors_wildcard": [
        "PCI-DSS 6.5.8",
        "ISO 27001 A.14.1.2",
    ],
    "cors_credentials": [
        "PCI-DSS 6.5.8",
        "ISO 27001 A.14.1.2",
    ],
    "cors_null_origin": [
        "PCI-DSS 6.5.8",
        "ISO 27001 A.14.1.2",
    ],
    "cors_sensitive_methods": [
        "PCI-DSS 6.5.8",
        "ISO 27001 A.14.1.2",
    ],
    "cors_sensitive_headers_exposed": [
        "PCI-DSS 6.5.8",
        "ISO 27001 A.14.1.2",
    ],
    # -- Directory listing / GraphQL ----------------------------------------
    "directory_listing": [
        "PCI-DSS 6.5.8",
        "ISO 27001 A.9.4.1",
    ],
    "graphql_introspection": [
        "PCI-DSS 6.5.8",
        "ISO 27001 A.14.1.2",
    ],
    # -- New security headers -----------------------------------------------
    "missing_cross_origin_opener_policy": [
        "ISO 27001 A.14.1.2",
    ],
    "missing_cross_origin_resource_policy": [
        "ISO 27001 A.14.1.2",
    ],
    "missing_x_permitted_cross_domain_policies": [
        "ISO 27001 A.14.1.2",
    ],
    # -- Typosquatting / brand protection -----------------------------------
    "typosquat_domains_found": [
        "ISO 27001 A.7.2.2",
    ],
    # -- Privacy compliance -------------------------------------------------
    "missing_privacy_policy": [
        "GDPR Art.13",
        "CCPA §1798.100",
    ],
    "missing_cookie_consent": [
        "GDPR Art.7",
        "ePrivacy Directive Art.5(3)",
    ],
    "missing_terms_of_service": [],
    "privacy_compliance_low": [
        "GDPR Art.13",
        "GDPR Art.14",
        "CCPA §1798.100",
    ],
}

# Prefix-based compliance tags for dynamic finding IDs (secret_*, ioc_*,
# cookie_*, path_*, breach_*).  Looked up when an exact match is not found.
_COMPLIANCE_PREFIX_MAP: dict[str, list[str]] = {
    "secret_": [
        "PCI-DSS 3.4",
        "PCI-DSS 6.5.x",
        "GDPR Art.32",
        "ISO 27001 A.10.1.1",
    ],
    "ioc_cryptominer": [
        "ISO 27001 A.12.2.1",
    ],
    "ioc_webshell_path": [
        "PCI-DSS 11.5",
        "ISO 27001 A.12.2.1",
    ],
    "ioc_credential_harvest": [
        "PCI-DSS 6.5.10",
        "ISO 27001 A.12.2.1",
    ],
    "ioc_hidden_iframe": [
        "ISO 27001 A.12.2.1",
    ],
    "ioc_obfuscated_js": [
        "ISO 27001 A.12.2.1",
    ],
    "ioc_seo_spam": [
        "ISO 27001 A.12.2.1",
    ],
    "ioc_defacement": [
        "ISO 27001 A.12.2.1",
    ],
    "ioc_suspicious_script": [
        "ISO 27001 A.12.2.1",
    ],
    "cookie_": [
        "PCI-DSS 6.5.10",
        "ISO 27001 A.14.1.2",
    ],
    "path_": [
        "PCI-DSS 6.5.8",
        "ISO 27001 A.9.4.1",
    ],
    "breach_": [
        "PCI-DSS 12.10",
        "GDPR Art.33",
        "GDPR Art.34",
    ],
}


def _resolve_compliance(finding_id: str) -> list[str]:
    """Return compliance tags for a finding ID (exact match, then prefix)."""
    exact = _COMPLIANCE_MAP.get(finding_id)
    if exact is not None:
        return list(exact)
    # Try prefix-based lookup — longest prefix first to prefer specific keys
    # (e.g. ``ioc_cryptominer`` before ``ioc_``).
    for prefix in sorted(_COMPLIANCE_PREFIX_MAP, key=len, reverse=True):
        if finding_id.startswith(prefix) or finding_id == prefix.rstrip("_"):
            return list(_COMPLIANCE_PREFIX_MAP[prefix])
    return []


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

    if result.dns and result.dns.ip_enrichment:
        for provider in result.dns.ip_enrichment.hosting_providers:
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
        elif h.status == "misconfigured" and h.header == "Access-Control-Allow-Origin":
            is_wildcard = h.value == "*"
            is_null = h.value == "null"
            if is_null:
                findings.append(PrioritizedFinding(
                    id="cors_null_origin",
                    title="CORS allows null origin (file:// bypass risk)",
                    category="security_headers",
                    severity="high",
                    classification=FindingClassification.confirmed_issue,
                    confidence="high",
                    owner=FindingOwner.customer,
                    why_it_matters=h.recommendation,
                    business_impact="Cross-origin data theft via sandboxed iframe or local file exploit",
                    evidence=[f"Access-Control-Allow-Origin: {h.value}"],
                    recommended_action=h.recommendation,
                    source_field="security_headers",
                ))
            else:
                findings.append(PrioritizedFinding(
                    id="cors_wildcard" if is_wildcard else "cors_credentials",
                    title="CORS wildcard allows any origin" if is_wildcard
                        else "CORS with credentials — verify trusted origin",
                    category="security_headers",
                    severity=h.severity,
                    classification=FindingClassification.confirmed_issue,
                    confidence="high",
                    owner=FindingOwner.customer,
                    why_it_matters=h.recommendation,
                    business_impact="Cross-origin data theft risk" if is_wildcard
                        else "Authenticated cross-origin request risk",
                    evidence=[f"Access-Control-Allow-Origin: {h.value}"],
                    recommended_action=h.recommendation,
                    source_field="security_headers",
                ))
        elif h.status == "misconfigured" and h.header == "Access-Control-Allow-Methods":
            findings.append(PrioritizedFinding(
                id="cors_sensitive_methods",
                title="CORS exposes sensitive HTTP methods",
                category="security_headers",
                severity=h.severity,
                classification=FindingClassification.confirmed_issue,
                confidence="high",
                owner=FindingOwner.customer,
                why_it_matters=h.recommendation,
                business_impact="Cross-origin state-changing requests risk",
                evidence=[f"Access-Control-Allow-Methods: {h.value}"],
                recommended_action=h.recommendation,
                source_field="security_headers",
            ))
        elif h.status == "misconfigured" and h.header == "Access-Control-Expose-Headers":
            findings.append(PrioritizedFinding(
                id="cors_sensitive_headers_exposed",
                title="CORS exposes sensitive response headers",
                category="security_headers",
                severity=h.severity,
                classification=FindingClassification.confirmed_issue,
                confidence="high",
                owner=FindingOwner.customer,
                why_it_matters=h.recommendation,
                business_impact="Credential or token leakage via cross-origin reads",
                evidence=[f"Access-Control-Expose-Headers: {h.value}"],
                recommended_action=h.recommendation,
                source_field="security_headers",
            ))
    return findings


def _classify_cookie_findings(
    result: DomainResult, platform: str, profile: PlatformProfile,
) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []

    for cookie in result.cookies:
        if not cookie.issues:
            continue

        is_platform = cookie.name in profile.known_cookies
        is_xsrf = cookie.name.upper().startswith("XSRF")

        if is_platform or is_xsrf:
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
    return findings


def _classify_ssl_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    ssl = result.ssl_certificate
    if not ssl or (not ssl.grade and not ssl.issues and ssl.cert_valid):
        return findings

    if not ssl.cert_valid:
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
    elif ssl.days_left and 0 < ssl.days_left <= 30:
        findings.append(PrioritizedFinding(
            id="ssl_expiring_soon",
            title=f"SSL certificate expires in {ssl.days_left} days",
            category="ssl",
            severity="high",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="An expired certificate will trigger browser warnings and break HTTPS.",
            business_impact="Imminent service disruption",
            evidence=[f"Expires: {ssl.valid_till}, {ssl.days_left} days remaining"],
            recommended_action="Renew the certificate before expiry. Enable auto-renewal if possible.",
            source_field="ssl_certificate",
        ))

    if ssl.cipher_bits and ssl.cipher_bits < 128:
        findings.append(PrioritizedFinding(
            id="ssl_weak_cipher",
            title=f"Weak cipher key length ({ssl.cipher_bits} bits)",
            category="ssl",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Cipher suites with less than 128-bit keys are vulnerable to brute-force attacks.",
            business_impact="Encrypted traffic may be decryptable",
            evidence=[f"Cipher: {ssl.cipher}, Key bits: {ssl.cipher_bits}"],
            recommended_action="Configure the server to use cipher suites with at least 128-bit keys (256-bit preferred).",
            source_field="ssl_certificate",
        ))

    if ssl.cipher and not ssl.pfs:
        findings.append(PrioritizedFinding(
            id="ssl_no_pfs",
            title="No Perfect Forward Secrecy (PFS)",
            category="ssl",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Without PFS, compromise of the server's private key allows decryption of all past traffic.",
            business_impact="Historical traffic decryption risk if key is compromised",
            evidence=[f"Cipher: {ssl.cipher} (no ECDHE/DHE key exchange)"],
            recommended_action="Configure the server to prefer ECDHE or DHE cipher suites for forward secrecy.",
            source_field="ssl_certificate",
        ))

    if ssl.key_type == "RSA" and 0 < ssl.key_size < 2048:
        findings.append(PrioritizedFinding(
            id="ssl_weak_key",
            title=f"Weak RSA key ({ssl.key_size} bits)",
            category="ssl",
            severity="high",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="RSA keys under 2048 bits are considered factorizable with modern computing resources.",
            business_impact="Certificate key may be compromised",
            evidence=[f"Key: {ssl.key_type} {ssl.key_size}-bit"],
            recommended_action="Reissue the certificate with at least a 2048-bit RSA key (3072+ recommended).",
            source_field="ssl_certificate",
        ))
    elif ssl.key_type == "EC" and 0 < ssl.key_size < 256:
        findings.append(PrioritizedFinding(
            id="ssl_weak_key",
            title=f"Weak EC key ({ssl.key_size} bits)",
            category="ssl",
            severity="high",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="EC keys under 256 bits do not provide adequate security for modern threats.",
            business_impact="Certificate key may be compromised",
            evidence=[f"Key: {ssl.key_type} {ssl.key_size}-bit"],
            recommended_action="Reissue the certificate with at least a P-256 (256-bit) EC key.",
            source_field="ssl_certificate",
        ))

    if ssl.grade and ssl.key_type and not ssl.has_sct:
        findings.append(PrioritizedFinding(
            id="ssl_no_sct",
            title="No embedded Certificate Transparency timestamps",
            category="ssl",
            severity="low",
            classification=FindingClassification.informational,
            confidence="medium",
            owner=FindingOwner.customer,
            why_it_matters="Certificates without SCTs may not comply with Certificate Transparency requirements.",
            business_impact="Limited — most CAs now include SCTs by default",
            evidence=["Certificate does not contain embedded SCT extension"],
            recommended_action="Ensure the CA includes SCTs when issuing/renewing the certificate.",
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
    if not result.dns or not result.dns.email_security:
        return findings
    es = result.dns.email_security
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

    # SPF deep intel findings.
    spf_intel = es.spf.intel
    if spf_intel:
        if spf_intel.exceeds_lookup_limit:
            findings.append(PrioritizedFinding(
                id="spf_lookup_limit_exceeded",
                title=f"SPF exceeds 10-lookup limit ({spf_intel.dns_lookup_count} lookups)",
                category="email_security",
                severity="medium",
                classification=FindingClassification.confirmed_issue,
                confidence="high",
                owner=FindingOwner.customer,
                why_it_matters="RFC 7208 limits SPF to 10 DNS lookups. Exceeding this causes receiving servers to return permerror, breaking email authentication.",
                business_impact="Email delivery failures and SPF bypass",
                evidence=[f"SPF chain requires {spf_intel.dns_lookup_count} DNS lookups (limit: 10)"],
                recommended_action="Flatten SPF includes by replacing nested includes with direct ip4/ip6 mechanisms, or use an SPF flattening service.",
                source_field="passive_intel.email_security.spf.intel",
            ))

        if spf_intel.services_detected:
            findings.append(PrioritizedFinding(
                id="spf_services_enumerated",
                title=f"{len(spf_intel.services_detected)} email service(s) identified via SPF",
                category="email_security",
                severity="info",
                classification=FindingClassification.informational,
                confidence="high",
                owner=FindingOwner.informational,
                why_it_matters="SPF includes reveal third-party email services used by the organisation.",
                business_impact="Attack surface awareness — each service is a potential phishing vector",
                evidence=[f"Services: {', '.join(spf_intel.services_detected)}"],
                recommended_action="Audit whether all listed services are still actively used. Remove unused includes.",
                source_field="passive_intel.email_security.spf.intel",
            ))

        if spf_intel.senders:
            countries = sorted({s.country_code for s in spf_intel.senders if s.country_code})
            providers = sorted({s.provider for s in spf_intel.senders if s.provider})
            findings.append(PrioritizedFinding(
                id="spf_senders_enumerated",
                title=f"{len(spf_intel.senders)} sender IP(s) resolved from SPF chain",
                category="email_security",
                severity="info",
                classification=FindingClassification.informational,
                confidence="high",
                owner=FindingOwner.informational,
                why_it_matters="SPF-authorized IP addresses reveal email sending infrastructure and hosting providers.",
                business_impact="Infrastructure intelligence for security assessment",
                evidence=[
                    f"IP ranges: {len(spf_intel.ip4_ranges)} IPv4, {len(spf_intel.ip6_ranges)} IPv6",
                    *(f"Provider: {p}" for p in providers[:5]),
                    *(f"Country: {c}" for c in countries[:5]),
                ],
                recommended_action="Review authorised sender list for unexpected or unused IP ranges.",
                source_field="passive_intel.email_security.spf.intel",
            ))

    # MTA-STS
    if not es.mta_sts.exists:
        findings.append(PrioritizedFinding(
            id="email_no_mta_sts",
            title="No MTA-STS policy configured",
            category="email_security",
            severity="low",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="MTA-STS enforces TLS for inbound email, preventing downgrade attacks.",
            business_impact="Email in transit may be intercepted via TLS stripping",
            evidence=["No _mta-sts TXT record found"],
            recommended_action="Publish an MTA-STS policy to enforce TLS for inbound SMTP connections.",
            source_field="passive_intel.email_security",
        ))

    # BIMI
    if not es.bimi.exists:
        findings.append(PrioritizedFinding(
            id="email_no_bimi",
            title="No BIMI record configured",
            category="email_security",
            severity="info",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.not_actionable,
            why_it_matters="BIMI displays your brand logo in email clients, improving trust and recognition.",
            business_impact="Missed brand visibility in email clients that support BIMI",
            evidence=["No default._bimi TXT record found"],
            recommended_action="Consider adding a BIMI record with your brand logo SVG and optional VMC certificate.",
            source_field="passive_intel.email_security",
        ))

    return findings


def _classify_dns_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    if not result.dns or not result.dns.records:
        return findings
    dns = result.dns.records
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

    if dns.hinfo_records:
        findings.append(PrioritizedFinding(
            id="dns_hinfo_exposed",
            title="HINFO records expose host OS/hardware details",
            category="dns",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="HINFO records reveal CPU and OS details, aiding targeted attacks.",
            business_impact="Information leakage enables targeted exploitation",
            evidence=[f"{r.cpu} / {r.os}" for r in dns.hinfo_records[:3]],
            recommended_action="Remove HINFO records unless explicitly required.",
            source_field="passive_intel.dns",
        ))

    if dns.loc_records:
        findings.append(PrioritizedFinding(
            id="dns_loc_exposed",
            title="LOC records expose physical location",
            category="dns",
            severity="low",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="LOC records publish geographic coordinates, potentially revealing data center or office locations.",
            business_impact="Physical security intelligence leakage",
            evidence=[f"lat={r.latitude:.4f}, lon={r.longitude:.4f}" for r in dns.loc_records[:3]],
            recommended_action="Remove LOC records if physical location should not be publicly disclosed.",
            source_field="passive_intel.dns",
        ))

    if dns.rp_records:
        findings.append(PrioritizedFinding(
            id="dns_rp_exposed",
            title="RP records expose responsible person contact",
            category="dns",
            severity="low",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="RP records reveal administrator email addresses, useful for social engineering.",
            business_impact="Contact information leakage for targeted phishing",
            evidence=[f"mbox={r.mbox}" for r in dns.rp_records[:3]],
            recommended_action="Remove RP records if admin contacts should not be publicly exposed.",
            source_field="passive_intel.dns",
        ))

    if dns.ds_records:
        findings.append(PrioritizedFinding(
            id="dns_ds_records_found",
            title="DNSSEC delegation signer (DS) records found",
            category="dns",
            severity="info",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.not_actionable,
            why_it_matters="DS records complete the DNSSEC chain of trust from the parent zone.",
            business_impact="Strong DNS integrity protection",
            evidence=[f"key_tag={r.key_tag}, algo={r.algorithm}" for r in dns.ds_records[:3]],
            recommended_action="No action needed — this is a positive finding.",
            source_field="passive_intel.dns",
        ))

    if dns.naptr_records:
        findings.append(PrioritizedFinding(
            id="dns_naptr_found",
            title="NAPTR records reveal service infrastructure",
            category="dns",
            severity="info",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.not_actionable,
            why_it_matters="NAPTR records reveal SIP/VoIP and other service endpoints.",
            business_impact="Infrastructure intelligence — SIP/VoIP services exposed",
            evidence=[f"service={r.service}, replacement={r.replacement}" for r in dns.naptr_records[:3]],
            recommended_action="Ensure exposed services are properly secured.",
            source_field="passive_intel.dns",
        ))

    return findings


_SENSITIVE_DISALLOW_PREFIXES = (
    "/admin", "/backup", "/api/internal", "/debug", "/.env",
    "/config", "/private", "/secret", "/staging", "/test",
)


def _classify_robots_sitemap(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    rt = result.robots_txt
    if rt and rt.found:
        sensitive = [
            r for r in rt.disallow_rules
            if any(r.lower().startswith(p) for p in _SENSITIVE_DISALLOW_PREFIXES)
        ]
        if sensitive:
            findings.append(PrioritizedFinding(
                id="robots_sensitive_disallow",
                title="robots.txt reveals sensitive paths",
                category="discovery",
                severity="low",
                classification=FindingClassification.informational,
                confidence="high",
                owner=FindingOwner.customer,
                why_it_matters="Disallow rules expose paths attackers can target directly.",
                business_impact="Reconnaissance accelerator — hidden paths disclosed",
                evidence=[f"Disallow: {p}" for p in sensitive[:5]],
                recommended_action="Review Disallow rules; ensure sensitive paths are access-controlled, not just hidden from crawlers.",
                source_field="robots_txt",
            ))

    sm = result.sitemap
    if sm and sm.found and sm.url_count > 50:
        findings.append(PrioritizedFinding(
            id="sitemap_large_surface",
            title=f"sitemap.xml exposes {sm.url_count} URLs",
            category="discovery",
            severity="info",
            classification=FindingClassification.informational,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Large sitemaps reveal the full URL surface area of the application.",
            business_impact="Attack surface mapping via publicly listed URLs",
            evidence=[f"{sm.url_count} URLs in sitemap.xml"],
            recommended_action="Verify all sitemap URLs are intended to be public.",
            source_field="sitemap",
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
    "@wix/", "thunderbolt-", "feature-", "@sentry/",
    "@next/", "next/", "@vercel/", "@shopify/",
    "@wordpress/", "@squarespace/", "@webflow/",
)


def is_vendor_source(path: str) -> bool:
    """Return True if a recovered source file path is a third-party/vendor file."""
    return any(path.startswith(p) or f"/{p}" in path for p in _VENDOR_PREFIXES)


def count_first_party_sources(files: list[str]) -> tuple[int, int]:
    """Return (first_party_count, vendor_count) for a list of recovered source paths."""
    vendor = sum(1 for f in files if is_vendor_source(f))
    return len(files) - vendor, vendor


def _classify_js_intel(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    if not result.js_intel:
        return findings

    ji = result.js_intel
    first_party_count, vendor_count = count_first_party_sources(ji.recovered_source_files)

    if first_party_count > 10:
        prop_exposure = "high"
    elif first_party_count > 0:
        prop_exposure = "low"
    else:
        prop_exposure = "none"

    if vendor_count and not first_party_count:
        ownership = "vendor"
    else:
        ownership = ""

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
    elif ji.sourcemaps_found and ownership == "vendor":
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

    return findings


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
    elif result.dns and result.dns.ip_enrichment:
        providers = result.dns.ip_enrichment.hosting_providers
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

    # DNS-based cloud service findings.
    if result.cloud_assets and result.cloud_assets.cloud_services:
        for svc in result.cloud_assets.cloud_services:
            key = f"dns:{svc.service}"
            if key not in seen:
                seen.add(key)
                assets.append(CloudAsset(
                    asset_type="database" if svc.is_database else "cloud_service",
                    identifier=f"{svc.service} ({svc.record_value})",
                    source="dns",
                ))

    return assets


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
    *,
    overall_grade: str = "",
    ransomware: RansomwareIndex | None = None,
    financial: FinancialImpact | None = None,
    compliance: list[CompliancePosture] | None = None,
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
    if overall_grade:
        parts.append(f"Overall grade: {overall_grade}.")
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

    if ransomware and ransomware.score >= 50:
        parts.append(f"Ransomware susceptibility is {ransomware.tier} ({ransomware.score}/100).")

    if financial and financial.estimated_annual_loss_high > 0:
        low_k = financial.estimated_annual_loss_low // 1000
        high_k = financial.estimated_annual_loss_high // 1000
        if high_k >= 1000:
            parts.append(f"Estimated annual loss exposure: ${low_k:,}K–${high_k:,}K.")
        elif high_k > 0:
            parts.append(f"Estimated annual loss exposure: ${low_k:,}K–${high_k:,}K.")

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
    if ssl and ssl.cert_valid and ssl.grade in ("A+", "A", "A-", "B+", "B"):
        positives.append(f"SSL/TLS certificate is valid (grade {ssl.grade})")
    es = result.dns.email_security if result.dns else None
    if es and not es.error and es.dmarc.exists and es.dmarc.policy in ("reject", "quarantine"):
        positives.append(f"DMARC enforcement active (p={es.dmarc.policy})")
    waf_names = [t.name for t in result.technologies if t.name in (
        "Cloudflare", "AWS CloudFront", "Fastly", "Akamai", "Imperva",
        "Sucuri", "F5 BIG-IP", "Azure Front Door",
    )]
    if waf_names:
        positives.append(f"WAF/CDN detected: {waf_names[0]}")
    if ransomware and ransomware.tier == "low":
        positives.append(f"Low ransomware susceptibility ({ransomware.score}/100)")

    concerns = [f.title for f in critical_high[:3]]

    # Top risks + recommendations from findings
    top_risks = [f.title for f in critical_high[:3]]
    recommendations = [f.recommended_action for f in critical_high[:3]]

    grades = _collect_grades(result)
    if overall_grade:
        grades["overall"] = overall_grade

    return ExecutiveSummary(
        risk_posture=risk_posture,
        narrative=" ".join(parts),
        key_positives=positives[:3],
        key_concerns=concerns,
        scan_coverage=scan_mode,
        overall_grade=overall_grade,
        grades=grades,
        top_risks=top_risks,
        recommendations=recommendations,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _classify_typosquatting_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    if not result.typosquatting or not result.typosquatting.registered_candidates:
        return findings
    for cand in result.typosquatting.registered_candidates[:10]:
        if cand.similarity_score >= 0.9:
            sev = "high"
        elif cand.similarity_score >= 0.8:
            sev = "medium"
        else:
            sev = "low"
        findings.append(PrioritizedFinding(
            id="typosquat_domains_found",
            title=f"Typosquat domain registered: {cand.domain}",
            category="brand_protection",
            severity=sev,
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Lookalike domains can be used for phishing, credential theft, or brand impersonation.",
            business_impact="Phishing and brand reputation risk",
            evidence=[
                f"Domain: {cand.domain}",
                f"Technique: {cand.technique}",
                f"Resolves to: {', '.join(cand.a_records[:3])}",
            ],
            recommended_action="Register this domain defensively or request takedown via the registrar.",
            source_field="typosquatting",
        ))
    return findings


def _classify_privacy_findings(result: DomainResult) -> list[PrioritizedFinding]:
    findings: list[PrioritizedFinding] = []
    if not result.privacy or result.privacy.error:
        return findings

    indicator_map = {ind.name: ind for ind in result.privacy.indicators}

    pp = indicator_map.get("privacy_policy")
    if pp and not pp.present:
        findings.append(PrioritizedFinding(
            id="missing_privacy_policy",
            title="No privacy policy detected",
            category="privacy_compliance",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="medium",
            owner=FindingOwner.customer,
            why_it_matters="Privacy policies are required under GDPR, CCPA, and most privacy regulations.",
            business_impact="Regulatory non-compliance risk",
            evidence=["No /privacy or /privacy-policy page returned HTTP 200"],
            recommended_action="Publish a privacy policy page and link to it from the website footer.",
            source_field="privacy",
        ))

    cc = indicator_map.get("cookie_consent_tool")
    if cc and not cc.present:
        findings.append(PrioritizedFinding(
            id="missing_cookie_consent",
            title="No cookie consent tool detected",
            category="privacy_compliance",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="medium",
            owner=FindingOwner.customer,
            why_it_matters="Cookie consent banners are required under GDPR and ePrivacy Directive for EU visitors.",
            business_impact="Regulatory non-compliance risk for EU-facing sites",
            evidence=["No consent management platform (OneTrust, Cookiebot, etc.) detected"],
            recommended_action="Implement a cookie consent tool such as OneTrust, Cookiebot, or Osano.",
            source_field="privacy",
        ))

    tos = indicator_map.get("terms_of_service")
    if tos and not tos.present:
        findings.append(PrioritizedFinding(
            id="missing_terms_of_service",
            title="No terms of service page detected",
            category="privacy_compliance",
            severity="low",
            classification=FindingClassification.informational,
            confidence="medium",
            owner=FindingOwner.customer,
            why_it_matters="Terms of service establish the legal framework for site usage.",
            business_impact="Legal protection gap",
            evidence=["No terms page found (checked /terms, /terms-of-service, /terms-of-use, /tos, and HTML links)"],
            recommended_action="Publish terms of service and link from the website footer.",
            source_field="privacy",
        ))

    if result.privacy.score < 40:
        findings.append(PrioritizedFinding(
            id="privacy_compliance_low",
            title=f"Low privacy compliance score ({result.privacy.score}/100)",
            category="privacy_compliance",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="medium",
            owner=FindingOwner.customer,
            why_it_matters="Low privacy compliance increases regulatory and reputational risk.",
            business_impact="Regulatory fines and customer trust erosion",
            evidence=[f"Privacy score: {result.privacy.score}/100, grade: {result.privacy.grade}"],
            recommended_action="Address missing privacy indicators: privacy policy, cookie consent, GDPR/CCPA compliance pages.",
            source_field="privacy",
        ))

    return findings


def _classify_cloud_findings(result: DomainResult) -> list[PrioritizedFinding]:
    """Emit findings for exposed cloud databases and public buckets."""
    findings: list[PrioritizedFinding] = []
    if not result.cloud_assets:
        return findings

    for svc in result.cloud_assets.cloud_services:
        if svc.is_database:
            findings.append(PrioritizedFinding(
                id="exposed_cloud_database",
                title=f"Cloud database endpoint in DNS: {svc.service}",
                category="cloud_infrastructure",
                severity=FindingSeverity.high,
                classification=FindingClassification.confirmed_issue,
                confidence="high",
                owner=FindingOwner.customer,
                why_it_matters="Database endpoints resolvable via public DNS may be accessible from the internet.",
                business_impact="Potential data breach if database accepts external connections",
                evidence=[
                    f"Service: {svc.service}",
                    f"Provider: {svc.provider}",
                    f"DNS record ({svc.record_type}): {svc.record_value}",
                ],
                recommended_action="Restrict database to private subnets/VPC. Remove public DNS records pointing to database endpoints.",
                source_field="cloud_assets",
            ))

    for bucket in result.cloud_assets.findings:
        if bucket.status == "public":
            findings.append(PrioritizedFinding(
                id="public_cloud_bucket",
                title=f"Public {bucket.provider} bucket: {bucket.bucket_name}",
                category="cloud_infrastructure",
                severity=FindingSeverity.critical,
                classification=FindingClassification.confirmed_issue,
                confidence="high",
                owner=FindingOwner.customer,
                why_it_matters="Publicly accessible cloud storage may expose sensitive data.",
                business_impact="Data breach via unauthenticated bucket access",
                evidence=[f"URL: {bucket.url}", f"Status: {bucket.status}"] + bucket.evidence,
                recommended_action="Restrict bucket access. Review and remove any sensitive data.",
                source_field="cloud_assets",
            ))

    return findings


def _classify_supply_chain_findings(result: DomainResult) -> list[PrioritizedFinding]:
    """Emit findings for third-party supply chain risks."""
    findings: list[PrioritizedFinding] = []
    if not result.supply_chain:
        return findings

    sc = result.supply_chain

    vuln_resources = [r for r in sc.resources if r.risk == "high" and r.library]
    for r in vuln_resources:
        findings.append(PrioritizedFinding(
            id="supply_chain_vulnerable_lib",
            title=f"Vulnerable library: {r.library} {r.version}",
            category="supply_chain",
            severity="high",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Known vulnerabilities in client-side libraries can be exploited for XSS or data theft.",
            business_impact="Client-side code execution risk",
            evidence=r.issues[:3],
            recommended_action=f"Upgrade {r.library} to the latest stable version.",
            source_field="supply_chain",
        ))

    compromised = [r for r in sc.resources if "COMPROMISED" in r.provider]
    for r in compromised:
        findings.append(PrioritizedFinding(
            id="supply_chain_compromised_provider",
            title=f"Resource from compromised provider: {r.provider}",
            category="supply_chain",
            severity="critical",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="This CDN provider has been compromised and used to serve malicious code.",
            business_impact="Active supply chain attack vector — arbitrary JS execution on visitors",
            evidence=[r.url],
            recommended_action="Remove immediately. Self-host the resource or migrate to a trusted CDN.",
            source_field="supply_chain",
        ))

    if sc.scripts_without_sri > 0:
        no_sri = [r for r in sc.resources if r.resource_type == "script" and not r.has_sri]
        findings.append(PrioritizedFinding(
            id="supply_chain_no_sri",
            title=f"{sc.scripts_without_sri} external script(s) without Subresource Integrity",
            category="supply_chain",
            severity="medium",
            classification=FindingClassification.confirmed_issue,
            confidence="high",
            owner=FindingOwner.customer,
            why_it_matters="Without SRI, a compromised CDN can inject malicious code into your site.",
            business_impact="Supply chain attack vector — CDN compromise leads to site compromise",
            evidence=[r.url for r in no_sri[:5]],
            recommended_action="Add integrity= and crossorigin= attributes to all external script tags.",
            source_field="supply_chain",
        ))

    return findings


# ---------------------------------------------------------------------------
# Overall domain risk grade (A+ to F)
# ---------------------------------------------------------------------------

_RISK_TO_GRADE: list[tuple[int, str]] = [
    (5, "A+"), (10, "A"), (15, "A-"),
    (25, "B+"), (35, "B"), (40, "B-"),
    (50, "C+"), (60, "C"), (65, "C-"),
    (75, "D+"), (80, "D"), (85, "D-"),
    (100, "F"),
]


def _compute_overall_grade(result: DomainResult, findings: list[PrioritizedFinding]) -> str:
    """Compute an aggregate A+ to F grade from FAIR risk + individual grades."""
    fair = result.fair_signals
    overall_risk = fair.overall_risk if fair else 50

    ssl_grade_score = _grade_to_score(result.ssl.grade if result.ssl else "")
    headers_grade_score = _grade_to_score(
        result.security.headers.grade if result.security and result.security.headers else ""
    )

    confirmed = [f for f in findings if f.classification == FindingClassification.confirmed_issue]
    crit_count = sum(1 for f in confirmed if f.severity == "critical")
    high_count = sum(1 for f in confirmed if f.severity == "high")
    finding_penalty = min(30, crit_count * 15 + high_count * 5)

    component_avg = (ssl_grade_score + headers_grade_score) / 2.0
    component_risk = max(0, 100 - component_avg)

    composite = int(round(overall_risk * 0.50 + component_risk * 0.25 + finding_penalty * 0.25))
    composite = max(0, min(100, composite))

    for threshold, grade in _RISK_TO_GRADE:
        if composite <= threshold:
            return grade
    return "F"


def _grade_to_score(grade: str) -> float:
    mapping = {
        "A+": 100, "A": 95, "A-": 90,
        "B+": 85, "B": 75, "B-": 70,
        "C+": 65, "C": 55, "C-": 50,
        "D+": 40, "D": 30, "D-": 25,
        "F": 0,
    }
    return mapping.get((grade or "").strip().upper(), 50)


def _collect_grades(result: DomainResult) -> dict[str, str]:
    grades: dict[str, str] = {}
    if result.ssl and result.ssl.grade:
        grades["ssl"] = result.ssl.grade
    if result.security and result.security.headers and result.security.headers.grade:
        grades["headers"] = result.security.headers.grade
    es = result.dns.email_security if result.dns else None
    if es and not es.error and hasattr(es, "grade") and es.grade:
        grades["email"] = es.grade
    if result.privacy and hasattr(result.privacy, "grade") and result.privacy.grade:
        grades["privacy"] = result.privacy.grade
    return grades


# ---------------------------------------------------------------------------
# Ransomware Susceptibility Index (RSI)
# ---------------------------------------------------------------------------

def _compute_ransomware_index(result: DomainResult) -> RansomwareIndex:
    """0-100 score predicting ransomware attack likelihood from existing signals."""
    score = 0
    factors: list[str] = []
    mitigations: list[str] = []

    # Exposed remote access ports (RDP 3389, SSH 22, VNC 5900, SMB 445)
    if result.port_scan and result.port_scan.open_ports:
        risky_ports = {3389, 445, 5900, 5901, 23}
        exposed = [p for p in result.port_scan.open_ports if p.port in risky_ports]
        if exposed:
            score += 25
            factors.append(f"Exposed remote access ports: {', '.join(str(p.port) for p in exposed)}")
        ssh_ports = [p for p in result.port_scan.open_ports if p.port == 22]
        if ssh_ports:
            score += 5
            factors.append("SSH port 22 exposed")

    # Weak email authentication (phishing entry vector)
    es = result.dns.email_security if result.dns else None
    if es and not es.error:
        if not es.dmarc.exists:
            score += 15
            factors.append("No DMARC record — phishing emails cannot be blocked")
        elif es.dmarc.policy == "none":
            score += 10
            factors.append("DMARC policy is 'none' — no email enforcement")
        else:
            mitigations.append(f"DMARC enforcement active (p={es.dmarc.policy})")

        if not es.spf.exists:
            score += 5
            factors.append("No SPF record")
        else:
            mitigations.append("SPF record configured")

    # Exposed credentials / secrets
    secrets_count = len(result.security.secrets) if result.security else 0
    if secrets_count:
        score += min(20, secrets_count * 10)
        factors.append(f"{secrets_count} exposed credential(s) / secret(s)")

    # Missing security headers (CSP, HSTS)
    hdr_grade = result.security.headers.grade if result.security and result.security.headers else ""
    if hdr_grade in ("F", "D-", "D", "D+"):
        score += 10
        factors.append(f"Weak security headers (grade {hdr_grade})")
    elif hdr_grade in ("A+", "A", "A-", "B+", "B"):
        mitigations.append(f"Strong security headers (grade {hdr_grade})")

    # Deprecated TLS / weak cipher
    ssl = result.ssl
    if ssl:
        if ssl.tls_version and ssl.tls_version < "TLSv1.2":
            score += 10
            factors.append(f"Deprecated TLS version: {ssl.tls_version}")
        elif ssl.grade in ("A+", "A", "A-"):
            mitigations.append(f"Strong TLS posture (grade {ssl.grade})")
        if not ssl.cert_valid:
            score += 5
            factors.append("Invalid SSL certificate")

    # Known CVEs with high EPSS
    vuln = result.vulnerabilities
    if vuln and vuln.cve_findings:
        high_epss = [c for c in vuln.cve_findings if (c.epss_score or 0) > 0.5]
        if high_epss:
            score += min(25, len(high_epss) * 10)
            factors.append(f"{len(high_epss)} CVE(s) with EPSS > 0.5 (likely exploited)")
        kev = [c for c in vuln.cve_findings if c.kev_listed]
        if kev:
            score += 15
            factors.append(f"{len(kev)} CVE(s) in CISA Known Exploited Vulnerabilities list")

    # No WAF detected
    waf_techs = [t for t in result.technologies if any(
        c in ("waf", "cdn") for c in (t.categories or [])
    )]
    if not waf_techs and not (result.waf and result.waf.detected):
        score += 5
        factors.append("No WAF or CDN protection detected")
    else:
        name = waf_techs[0].name if waf_techs else (result.waf.firewall if result.waf else "")
        if name:
            mitigations.append(f"WAF/CDN protection: {name}")

    # Breach history
    if result.breaches:
        score += min(10, len(result.breaches) * 3)
        factors.append(f"{len(result.breaches)} previous breach(es) on record")

    # Exposed admin panels / sensitive paths
    if result.security and result.security.sensitive_paths:
        admin_paths = [p for p in result.security.sensitive_paths
                       if p.status_code == 200 and any(
                           kw in (p.path or "").lower()
                           for kw in ("admin", "login", "wp-admin", "phpmyadmin", "cpanel")
                       )]
        if admin_paths:
            score += 10
            factors.append(f"{len(admin_paths)} exposed admin panel(s)")

    # Nuclei findings
    if vuln and vuln.nuclei and vuln.nuclei.findings:
        crit_high = [f for f in vuln.nuclei.findings if f.severity in ("critical", "high")]
        if crit_high:
            score += min(15, len(crit_high) * 5)
            factors.append(f"{len(crit_high)} critical/high Nuclei finding(s)")

    score = max(0, min(100, score))

    if score >= 75:
        tier = "critical"
    elif score >= 50:
        tier = "high"
    elif score >= 25:
        tier = "medium"
    else:
        tier = "low"

    return RansomwareIndex(score=score, tier=tier, factors=factors, mitigations=mitigations)


# ---------------------------------------------------------------------------
# Financial risk quantification
# ---------------------------------------------------------------------------

_INCIDENT_COST_BASE = {
    "critical": (2_500_000, 8_000_000),
    "high":     (500_000,   3_000_000),
    "medium":   (100_000,   800_000),
    "low":      (10_000,    150_000),
}


def _compute_financial_impact(result: DomainResult) -> FinancialImpact:
    """Estimate financial exposure using FAIR risk + IBM CODB 2024 benchmarks."""
    fair = result.fair_signals
    overall_risk = fair.overall_risk if fair else 0
    lef = fair.loss_event_frequency if fair else 0

    if overall_risk >= 75:
        bracket = "critical"
    elif overall_risk >= 50:
        bracket = "high"
    elif overall_risk >= 25:
        bracket = "medium"
    else:
        bracket = "low"

    base_low, base_high = _INCIDENT_COST_BASE[bracket]

    factors: list[str] = []

    # Adjust based on breach history data types
    multiplier = 1.0
    if result.breaches:
        has_financial = any(
            any(t in b.data_types for t in ("Credit cards", "Bank account numbers", "Payment histories"))
            for b in result.breaches if b.data_types
        )
        if has_financial:
            multiplier += 0.5
            factors.append("Financial data in breach history (+50% cost)")
        has_health = any(
            "Health records" in (b.data_types or [])
            for b in result.breaches
        )
        if has_health:
            multiplier += 0.3
            factors.append("Health data in breach history (+30% cost)")

    # Credential exposure amplifies cost
    if result.security and result.security.secrets:
        crit_secrets = [s for s in result.security.secrets if s.severity == "critical"]
        if crit_secrets:
            multiplier += 0.25
            factors.append(f"{len(crit_secrets)} critical credential(s) exposed (+25% cost)")

    # Cloud database exposure
    if result.cloud_assets:
        dbs = [s for s in result.cloud_assets.cloud_services if s.is_database]
        if dbs:
            multiplier += 0.4
            factors.append(f"{len(dbs)} cloud database(s) exposed (+40% cost)")

    incident_low = int(base_low * multiplier)
    incident_high = int(base_high * multiplier)

    # Annualised: probability from FAIR LEF (0-100 → 0%-100% annual probability)
    annual_prob = lef / 100.0
    annual_low = int(incident_low * annual_prob)
    annual_high = int(incident_high * annual_prob)

    factors.append(f"FAIR risk score: {overall_risk}/100 ({bracket})")
    factors.append(f"Annualised probability: {annual_prob:.0%}")
    factors.append("Benchmarks: IBM Cost of a Data Breach 2024 ($4.88M avg)")

    return FinancialImpact(
        estimated_annual_loss_low=annual_low,
        estimated_annual_loss_high=annual_high,
        single_incident_cost_low=incident_low,
        single_incident_cost_high=incident_high,
        factors=factors,
    )


# ---------------------------------------------------------------------------
# Compliance readiness reports
# ---------------------------------------------------------------------------

_PCI_DSS_CONTROLS: list[tuple[str, str]] = [
    ("PCI-DSS 3.4", "Render PAN unreadable wherever stored"),
    ("PCI-DSS 4.1", "Use strong cryptography and security protocols"),
    ("PCI-DSS 6.2", "Protect systems from known vulnerabilities"),
    ("PCI-DSS 6.5.5", "Prevent information leakage"),
    ("PCI-DSS 6.5.6", "Address high-risk vulnerabilities"),
    ("PCI-DSS 6.5.7", "Prevent cross-site scripting"),
    ("PCI-DSS 6.5.8", "Prevent improper access control"),
    ("PCI-DSS 6.5.10", "Prevent broken authentication and session management"),
    ("PCI-DSS 6.5.x", "Secure development practices"),
    ("PCI-DSS 12.10", "Maintain an incident response plan"),
]

_ISO27001_CONTROLS: list[tuple[str, str]] = [
    ("ISO 27001 A.7.2.2", "Information security awareness and training"),
    ("ISO 27001 A.9.4.1", "Information access restriction"),
    ("ISO 27001 A.10.1.1", "Policy on the use of cryptographic controls"),
    ("ISO 27001 A.12.2.1", "Controls against malware"),
    ("ISO 27001 A.12.6.1", "Management of technical vulnerabilities"),
    ("ISO 27001 A.13.2.1", "Information transfer policies and procedures"),
    ("ISO 27001 A.14.1.2", "Securing application services on public networks"),
    ("ISO 27001 A.15.1.1", "Information security policy for supplier relationships"),
]

_GDPR_CONTROLS: list[tuple[str, str]] = [
    ("GDPR Art.32", "Security of processing"),
    ("GDPR Art.33", "Notification of breach to supervisory authority"),
    ("GDPR Art.34", "Communication of breach to data subject"),
]


def _compute_compliance_posture(
    findings: list[PrioritizedFinding],
) -> list[CompliancePosture]:
    """Build per-framework compliance readiness from tagged findings."""
    failing_tags: set[str] = set()
    tag_to_findings: dict[str, list[str]] = {}
    for f in findings:
        if f.classification != FindingClassification.confirmed_issue:
            continue
        for tag in f.compliance:
            failing_tags.add(tag)
            tag_to_findings.setdefault(tag, []).append(f.id)

    postures: list[CompliancePosture] = []

    for framework_name, controls_list in [
        ("PCI-DSS 4.0", _PCI_DSS_CONTROLS),
        ("ISO 27001", _ISO27001_CONTROLS),
        ("GDPR", _GDPR_CONTROLS),
    ]:
        controls: list[ComplianceControl] = []
        passing = 0
        failing = 0
        for control_id, control_name in controls_list:
            if control_id in failing_tags:
                controls.append(ComplianceControl(
                    control_id=control_id,
                    control_name=control_name,
                    status="fail",
                    findings=tag_to_findings.get(control_id, []),
                ))
                failing += 1
            else:
                controls.append(ComplianceControl(
                    control_id=control_id,
                    control_name=control_name,
                    status="pass",
                ))
                passing += 1

        total = len(controls_list)
        readiness = int(round(passing / total * 100)) if total else 0

        postures.append(CompliancePosture(
            framework=framework_name,
            controls_tested=total,
            controls_passing=passing,
            controls_failing=failing,
            controls_not_tested=0,
            readiness_score=readiness,
            controls=controls,
        ))

    return postures


def build_easm_report(
    result: DomainResult, *, scan_mode: str = "full",
) -> EASMReport:
    """Build a business-grade EASM report from a populated DomainResult."""
    try:
        platform, profile = _detect_primary_platform(result)

        all_findings: list[PrioritizedFinding] = []
        all_findings.extend(_classify_header_findings(result, platform, profile))
        all_findings.extend(_classify_cookie_findings(result, platform, profile))
        all_findings.extend(_classify_ssl_findings(result))
        all_findings.extend(_classify_secret_findings(result))
        all_findings.extend(_classify_path_findings(result))
        all_findings.extend(_classify_ioc_findings(result))
        all_findings.extend(_classify_email_security(result))
        all_findings.extend(_classify_dns_findings(result))
        all_findings.extend(_classify_breach_findings(result))
        all_findings.extend(_classify_robots_sitemap(result))
        all_findings.extend(_classify_js_intel(result))
        all_findings.extend(_classify_typosquatting_findings(result))
        all_findings.extend(_classify_privacy_findings(result))
        all_findings.extend(_classify_cloud_findings(result))
        all_findings.extend(_classify_supply_chain_findings(result))

        sorted_findings = _sort_findings(all_findings)

        # Apply compliance framework tags
        for finding in sorted_findings:
            finding.compliance = _resolve_compliance(finding.id)

        # Build compliance summary counts
        framework_counts: dict[str, int] = {}
        for f in sorted_findings:
            for tag in f.compliance:
                framework = tag.split(" ")[0]
                framework_counts[framework] = framework_counts.get(framework, 0) + 1

        asset_context = _infer_asset_context(result, platform, profile)
        cloud_assets = _detect_cloud_assets(result)
        recon_artifacts = _extract_recon_artifacts(result)

        # Compute new enterprise features
        overall_grade = _compute_overall_grade(result, sorted_findings)
        ransomware = _compute_ransomware_index(result)
        financial = _compute_financial_impact(result)
        compliance = _compute_compliance_posture(sorted_findings)

        executive = _build_executive_summary(
            sorted_findings, result, platform, scan_mode,
            overall_grade=overall_grade,
            ransomware=ransomware,
            financial=financial,
            compliance=compliance,
        )

        confirmed = sum(1 for f in sorted_findings if f.classification == FindingClassification.confirmed_issue)
        plat_beh = sum(1 for f in sorted_findings if f.classification == FindingClassification.platform_behavior)
        info_ct = sum(1 for f in sorted_findings if f.classification == FindingClassification.informational)

        return EASMReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            scan_mode=scan_mode,
            overall_grade=overall_grade,
            executive_summary=executive,
            ransomware_susceptibility=ransomware,
            financial_impact=financial,
            compliance_posture=compliance,
            asset_context=asset_context,
            cloud_assets=cloud_assets,
            recon_artifacts=recon_artifacts,
            prioritized_findings=sorted_findings,
            total_findings=len(sorted_findings),
            confirmed_issues=confirmed,
            platform_behaviors=plat_beh,
            informational_count=info_ct,
            compliance_summary=framework_counts,
            platform_detected=platform,
        )
    except Exception as exc:
        logger.warning("EASM report generation failed for %s: %s", result.target, exc)
        return EASMReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            scan_mode=scan_mode,
        )


__all__ = ["build_easm_report"]
