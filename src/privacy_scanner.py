"""Privacy compliance indicator detection."""

from __future__ import annotations

import re

from .models import (
    PrivacyComplianceResult,
    PrivacyIndicator,
    SensitivePathFinding,
    TechFinding,
)

_PRIVACY_PAGE_PATHS = frozenset({
    "/privacy", "/privacy-policy", "/privacy.html",
})
_COOKIE_POLICY_PATHS = frozenset({
    "/cookie-policy", "/cookies",
})
_TERMS_PATHS = frozenset({
    "/terms", "/terms-of-service",
})
_GDPR_PATHS = frozenset({"/gdpr", "/data-request"})
_CCPA_PATHS = frozenset({"/ccpa"})
_DNT_PATHS = frozenset({"/.well-known/dnt-policy.txt"})

_PRIVACY_LINK_RE = re.compile(
    r'<a\b[^>]*href=["\'][^"\']*(?:privacy|datenschutz)[^"\']*["\'][^>]*>',
    re.IGNORECASE,
)
_DO_NOT_SELL_RE = re.compile(
    r"do\s+not\s+sell",
    re.IGNORECASE,
)


def _score_to_grade(score: int) -> str:
    if score >= 80:
        return "A"
    if score >= 60:
        return "B"
    if score >= 40:
        return "C"
    if score >= 20:
        return "D"
    return "F"


def _path_found(paths: list[SensitivePathFinding], target_paths: frozenset[str]) -> list[str]:
    """Return evidence strings for paths that returned 200."""
    return [
        f"{p.path} (HTTP {p.status_code})"
        for p in paths
        if p.path in target_paths and p.status_code == 200
    ]


def analyze_privacy_compliance(
    domain: str,
    sensitive_paths: list[SensitivePathFinding],
    technologies: list[TechFinding],
    landing_html: str = "",
) -> PrivacyComplianceResult:
    """Assess privacy compliance from scan data."""
    indicators: list[PrivacyIndicator] = []
    score = 0

    # 1. Privacy policy
    evidence = _path_found(sensitive_paths, _PRIVACY_PAGE_PATHS)
    if not evidence and landing_html and _PRIVACY_LINK_RE.search(landing_html):
        evidence = ["Privacy link found in landing page HTML"]
    present = bool(evidence)
    indicators.append(PrivacyIndicator(name="privacy_policy", present=present, evidence=evidence))
    if present:
        score += 25

    # 2. Cookie consent tool
    consent_tools = [
        t for t in technologies
        if "consent_management" in t.categories
    ]
    consent_evidence = [f"{t.name} detected" for t in consent_tools]
    consent_present = bool(consent_tools)
    indicators.append(PrivacyIndicator(
        name="cookie_consent_tool", present=consent_present, evidence=consent_evidence,
    ))
    consent_tool_name = consent_tools[0].name if consent_tools else ""
    if consent_present:
        score += 25

    # 3. Terms of service
    terms_evidence = _path_found(sensitive_paths, _TERMS_PATHS)
    terms_present = bool(terms_evidence)
    indicators.append(PrivacyIndicator(name="terms_of_service", present=terms_present, evidence=terms_evidence))
    if terms_present:
        score += 10

    # 4. GDPR indicators
    gdpr_evidence = _path_found(sensitive_paths, _GDPR_PATHS)
    cookie_policy_evidence = _path_found(sensitive_paths, _COOKIE_POLICY_PATHS)
    if cookie_policy_evidence:
        gdpr_evidence.extend(cookie_policy_evidence)
    if consent_present:
        gdpr_evidence.append(f"Consent tool ({consent_tool_name}) supports GDPR")
    gdpr_present = bool(gdpr_evidence)
    indicators.append(PrivacyIndicator(name="gdpr_indicators", present=gdpr_present, evidence=gdpr_evidence))
    if gdpr_present:
        score += 15

    # 5. CCPA indicators
    ccpa_evidence = _path_found(sensitive_paths, _CCPA_PATHS)
    if landing_html and _DO_NOT_SELL_RE.search(landing_html):
        ccpa_evidence.append('"Do Not Sell" text found in landing page')
    ccpa_present = bool(ccpa_evidence)
    indicators.append(PrivacyIndicator(name="ccpa_indicators", present=ccpa_present, evidence=ccpa_evidence))
    if ccpa_present:
        score += 15

    # 6. DNT policy
    dnt_evidence = _path_found(sensitive_paths, _DNT_PATHS)
    dnt_present = bool(dnt_evidence)
    indicators.append(PrivacyIndicator(name="dnt_policy", present=dnt_present, evidence=dnt_evidence))
    if dnt_present:
        score += 10

    return PrivacyComplianceResult(
        domain=domain,
        score=score,
        grade=_score_to_grade(score),
        indicators=indicators,
        consent_tool=consent_tool_name,
    )
