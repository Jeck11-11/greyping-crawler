"""FAIR (Factor Analysis of Information Risk) signal builder.

Takes a ``DomainResult`` already populated by the scanner and maps the
evidence onto the four FAIR factors (Threat Event Frequency, Vulnerability,
Control Strength, Loss Magnitude). Derives Loss Event Frequency and an
overall risk score from those factors so a downstream system (e.g. Xano)
can construct a consistent risk profile.

Every score is 0-100.

    Risk               = Loss Event Frequency × Loss Magnitude
    Loss Event Freq.   = Threat Event Frequency × Vulnerability
    Vulnerability      = Threat Capability vs. Resistance Strength

Control Strength acts as an attenuator on Loss Event Frequency — strong
defences reduce (but never fully eliminate) the probability a threat
engagement becomes a loss event.
"""

from __future__ import annotations

import logging
from typing import Any

from .models import (
    DomainResult,
    FAIRFactor,
    FAIRSignal,
    FAIRSignals,
)

logger = logging.getLogger(__name__)


# Grades produced by security_headers and ssl_checker → normalised score.
_GRADE_TO_SCORE: dict[str, int] = {
    "A+": 100, "A": 95, "A-": 90,
    "B+": 85, "B": 75, "B-": 70,
    "C+": 65, "C": 55, "C-": 50,
    "D+": 40, "D": 30, "D-": 25,
    "F": 0,
}

_SEVERITY_TO_SCORE: dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 10,
}

# Tech categories that meaningfully raise Threat Event Frequency.
_HIGH_TARGET_CATEGORIES: frozenset[str] = frozenset(
    {"cms", "ecommerce", "webmail", "vpn", "remote_access", "database"}
)

# Tech names/categories that indicate a WAF / CDN sitting in front of the
# target — directly boosts Control Strength.
_WAF_CDN_NAMES: frozenset[str] = frozenset(
    {
        "Cloudflare", "AWS CloudFront", "Fastly", "Akamai",
        "Imperva", "Sucuri", "F5 BIG-IP", "Azure Front Door",
    }
)
_WAF_CDN_CATEGORIES: frozenset[str] = frozenset({"cdn", "waf"})


def _grade_score(grade: str) -> int:
    """Map a letter grade (A+..F) onto 0-100. Unknown grades → 50."""
    if not grade:
        return 50
    return _GRADE_TO_SCORE.get(grade.strip().upper(), 50)


def _severity_score(severity: str) -> int:
    """Map a severity string onto 0-100. Unknown → 50."""
    return _SEVERITY_TO_SCORE.get((severity or "").lower(), 50)


def _aggregate_findings_score(items: list, attr: str = "severity") -> int:
    """Score a list of findings by the worst severity, amplified by count.

    One high-severity finding already matters; several compound but saturate
    at 100. Empty list → 0.
    """
    if not items:
        return 0
    severities = [_severity_score(getattr(i, attr, "")) for i in items]
    worst = max(severities)
    # Each additional finding adds 5 points, capped at 100.
    return min(100, worst + 5 * (len(items) - 1))


def _factor_from_signals(signals: list[FAIRSignal], notes: str = "") -> FAIRFactor:
    """Weighted-average the signals into a single factor score."""
    if not signals:
        return FAIRFactor(score=0, signals=[], notes=notes or "No evidence available.")
    total_weight = sum(s.weight for s in signals) or 1.0
    weighted = sum(s.score * s.weight for s in signals)
    return FAIRFactor(
        score=int(round(weighted / total_weight)),
        signals=signals,
        notes=notes,
    )


def _neutral(factor: FAIRFactor) -> int:
    """For derivation, a factor with no signals is treated as neutral (50).

    This prevents a passive scan (which has no Control Strength evidence)
    from collapsing overall_risk to zero.
    """
    return factor.score if factor.signals else 50


def _confidence_for_mode(mode: str) -> str:
    return {
        "passive": "low",
        "lighttouch": "medium",
        "standard": "high",
        "full": "high",
    }.get(mode, "low")


# ---------------------------------------------------------------------------
# Factor builders
# ---------------------------------------------------------------------------

def _build_threat_event_frequency(result: DomainResult) -> FAIRFactor:
    """TEF: how often a threat actor is likely to engage with this target."""
    signals: list[FAIRSignal] = []

    passive = result.passive_intel

    # Subdomain / CT exposure — more public surface = more TEF.
    subdomain_count = (
        len(passive.ct.subdomains) if passive and passive.ct else 0
    )
    if subdomain_count:
        # 1 sub → 10, 5 → 50, 10+ → 100 (capped).
        score = min(100, subdomain_count * 10)
        signals.append(FAIRSignal(
            name="attack_surface_breadth",
            score=score,
            weight=1.2,
            evidence=[f"{subdomain_count} subdomains seen in CT logs"],
        ))

    # Wayback history — long public history = more time attackers had to
    # notice, and indicates an established public footprint.
    wb_count = (
        passive.wayback.snapshot_count if passive and passive.wayback else 0
    )
    if wb_count:
        # 1 snapshot → 5, 50 → 50, 200+ → 100.
        score = min(100, wb_count // 2)
        signals.append(FAIRSignal(
            name="public_exposure_history",
            score=score,
            weight=0.6,
            evidence=[f"{wb_count} archive.org snapshots recorded"],
        ))

    # High-target tech stacks.
    target_tech = [
        t for t in result.technologies
        if any(c in _HIGH_TARGET_CATEGORIES for c in t.categories)
    ]
    if target_tech:
        signals.append(FAIRSignal(
            name="high_target_tech_stack",
            score=min(100, 60 + 10 * len(target_tech)),
            weight=1.0,
            evidence=[f"{t.name} ({'/'.join(t.categories)})" for t in target_tech[:5]],
        ))

    # API endpoints leaked via JS bundles.
    api_count = (
        len(result.js_intel.api_endpoints) if result.js_intel else 0
    )
    if api_count:
        signals.append(FAIRSignal(
            name="api_endpoint_exposure",
            score=min(100, api_count * 8),
            weight=0.8,
            evidence=[f"{api_count} API endpoints discovered in JS bundles"],
        ))

    # Contact attack surface — more emails visible = more phishing targets.
    email_count = len(result.emails)
    if email_count:
        signals.append(FAIRSignal(
            name="contact_attack_surface",
            score=min(100, email_count * 15),
            weight=0.5,
            evidence=[f"{email_count} email addresses harvested"],
        ))

    return _factor_from_signals(
        signals,
        notes="Higher TEF means threat actors are more likely to engage this target.",
    )


def _build_vulnerability(result: DomainResult) -> FAIRFactor:
    """Vulnerability: likelihood a threat engagement becomes a loss event."""
    signals: list[FAIRSignal] = []

    # Exposed secrets — direct, high-signal vulnerability.
    if result.secrets:
        signals.append(FAIRSignal(
            name="exposed_secrets",
            score=_aggregate_findings_score(result.secrets),
            weight=1.5,
            evidence=[
                f"{s.secret_type} ({s.severity}) in {s.location}"
                for s in result.secrets[:5]
            ],
        ))

    # Sensitive paths reachable on the target.
    if result.sensitive_paths:
        signals.append(FAIRSignal(
            name="sensitive_paths_exposed",
            score=_aggregate_findings_score(result.sensitive_paths),
            weight=1.3,
            evidence=[
                f"{p.path} → {p.status_code} ({p.severity})"
                for p in result.sensitive_paths[:5]
            ],
        ))

    # IoCs detected on the site.
    if result.ioc_findings:
        signals.append(FAIRSignal(
            name="ioc_presence",
            score=_aggregate_findings_score(result.ioc_findings),
            weight=1.4,
            evidence=[
                f"{i.ioc_type} ({i.severity})" for i in result.ioc_findings[:5]
            ],
        ))

    # SSL issues. Only emit if check_ssl actually ran (grade set) OR
    # there are concrete issues on record — the default SSLCertResult has
    # is_valid=True and an empty grade, which shouldn't register as
    # "TLS weakness".
    ssl = result.ssl_certificate
    if ssl and (ssl.issues or (ssl.grade and not ssl.is_valid)):
        inv = 100 - _grade_score(ssl.grade)
        if not ssl.is_valid:
            inv = max(inv, 80)
        signals.append(FAIRSignal(
            name="tls_weaknesses",
            score=inv,
            weight=0.9,
            evidence=ssl.issues[:3] if ssl.issues else ["TLS cert invalid"],
        ))

    # Missing security headers (invert the grade).
    headers = result.security_headers
    missing = [h for h in headers.findings if h.status == "missing"]
    if missing:
        inv = 100 - _grade_score(headers.grade)
        signals.append(FAIRSignal(
            name="missing_security_headers",
            score=inv,
            weight=1.0,
            evidence=[f"{h.header} ({h.severity})" for h in missing[:5]],
        ))

    # Cookies with security issues.
    bad_cookies = [c for c in result.cookies if c.issues]
    if bad_cookies:
        signals.append(FAIRSignal(
            name="insecure_cookies",
            score=min(100, 40 + 10 * len(bad_cookies)),
            weight=0.7,
            evidence=[f"{c.name}: {', '.join(c.issues)}" for c in bad_cookies[:3]],
        ))

    # Email authentication gaps — missing SPF/DMARC is a phishing vector.
    email_sec = (
        result.passive_intel.email_security
        if result.passive_intel else None
    )
    if email_sec and not email_sec.error:
        issues: list[str] = []
        score = 0
        if not email_sec.spf.exists:
            issues.append("No SPF record")
            score += 40
        elif email_sec.spf.all_qualifier in ("+all", "?all"):
            issues.append(f"SPF uses {email_sec.spf.all_qualifier} (weak)")
            score += 25
        if not email_sec.dmarc.exists:
            issues.append("No DMARC record — domain spoofing is trivial")
            score += 40
        elif email_sec.dmarc.policy == "none":
            issues.append("DMARC p=none — monitoring only, no enforcement")
            score += 20
        if not email_sec.dkim.selectors_found:
            issues.append("No DKIM selectors found")
            score += 20
        if issues:
            signals.append(FAIRSignal(
                name="email_auth_missing",
                score=min(100, score),
                weight=1.2,
                evidence=issues,
            ))

    return _factor_from_signals(
        signals,
        notes="Higher Vulnerability means a threat engagement is more likely to succeed.",
    )


def _build_control_strength(result: DomainResult) -> FAIRFactor:
    """Control Strength: quality of defences observed.

    Higher is better (more defences seen). Acts as an attenuator on Loss
    Event Frequency in the derivation step.
    """
    signals: list[FAIRSignal] = []

    # WAF / CDN in front of the target.
    waf_names = [
        t.name for t in result.technologies
        if t.name in _WAF_CDN_NAMES
        or any(c in _WAF_CDN_CATEGORIES for c in t.categories)
    ]
    if waf_names:
        signals.append(FAIRSignal(
            name="waf_or_cdn_detected",
            score=85,
            weight=1.4,
            evidence=[f"{n} fronting the target" for n in waf_names[:3]],
        ))

    # Security headers — straight grade. Require a grade OR findings,
    # since the default SecurityHeadersResult has both empty.
    headers = result.security_headers
    if headers and (headers.grade or headers.findings):
        signals.append(FAIRSignal(
            name="security_headers_posture",
            score=_grade_score(headers.grade),
            weight=1.2,
            evidence=[f"grade={headers.grade or 'unknown'}, score={headers.score}"],
        ))

    # TLS posture — only when check_ssl has produced a grade. The default
    # SSLCertResult has is_valid=True and no grade, which shouldn't count
    # as positive evidence of a defence.
    ssl = result.ssl_certificate
    if ssl and ssl.grade:
        score = _grade_score(ssl.grade)
        if not ssl.is_valid:
            score = min(score, 20)
        signals.append(FAIRSignal(
            name="tls_posture",
            score=score,
            weight=1.1,
            evidence=[f"grade={ssl.grade}, valid={ssl.is_valid}"],
        ))

    # Cookie hardening — ratio of cookies that are clean.
    if result.cookies:
        clean = sum(1 for c in result.cookies if not c.issues)
        ratio = clean / len(result.cookies)
        signals.append(FAIRSignal(
            name="cookie_hardening",
            score=int(round(ratio * 100)),
            weight=0.6,
            evidence=[f"{clean}/{len(result.cookies)} cookies have no issues"],
        ))

    # Email authentication posture — SPF + DMARC + DKIM = strong phishing defence.
    email_sec = (
        result.passive_intel.email_security
        if result.passive_intel else None
    )
    if email_sec and not email_sec.error and email_sec.grade:
        signals.append(FAIRSignal(
            name="email_security_posture",
            score=_grade_score(email_sec.grade),
            weight=1.0,
            evidence=[
                f"email security grade={email_sec.grade}",
                f"SPF={'yes' if email_sec.spf.exists else 'no'}",
                f"DMARC={email_sec.dmarc.policy or 'missing'}",
                f"DKIM={len(email_sec.dkim.selectors_found)} selector(s) found",
            ],
        ))

    return _factor_from_signals(
        signals,
        notes="Higher Control Strength means stronger observed defences (WAF, TLS, headers, cookies, email auth).",
    )


def _build_loss_magnitude(result: DomainResult) -> FAIRFactor:
    """Loss Magnitude: potential impact of a loss event."""
    signals: list[FAIRSignal] = []

    # Credential exposure — secrets leaked = direct loss potential.
    if result.secrets:
        signals.append(FAIRSignal(
            name="credential_exposure",
            score=_aggregate_findings_score(result.secrets),
            weight=1.5,
            evidence=[f"{s.secret_type} exposed" for s in result.secrets[:5]],
        ))

    # Breach history — already-realised losses + data type breadth.
    if result.breaches:
        data_types = set()
        for b in result.breaches:
            data_types.update(b.data_types)
        # Each breach adds 15, each distinct data class adds 5, capped 100.
        score = min(100, 40 + 15 * len(result.breaches) + 5 * len(data_types))
        signals.append(FAIRSignal(
            name="breach_history",
            score=score,
            weight=1.3,
            evidence=[
                f"{b.breach_name or b.source} ({', '.join(b.data_types[:3])})"
                for b in result.breaches[:5]
            ],
        ))

    # IoC categories implying sensitive data handling gone wrong.
    sensitive_iocs = [
        i for i in result.ioc_findings
        if i.ioc_type in ("credential_harvest", "webshell_path", "defacement")
    ]
    if sensitive_iocs:
        signals.append(FAIRSignal(
            name="sensitive_data_iocs",
            score=_aggregate_findings_score(sensitive_iocs),
            weight=1.1,
            evidence=[f"{i.ioc_type}" for i in sensitive_iocs[:3]],
        ))

    # Broad email surface = broader phishing blast radius if credentials leak.
    email_count = len(result.emails)
    if email_count >= 5:
        signals.append(FAIRSignal(
            name="phishing_blast_radius",
            score=min(100, email_count * 5),
            weight=0.6,
            evidence=[f"{email_count} distinct emails available for phishing"],
        ))

    # Public-footprint multiplier (if we have passive data).
    passive = result.passive_intel
    if passive and passive.wayback and passive.wayback.snapshot_count > 50:
        signals.append(FAIRSignal(
            name="public_footprint_multiplier",
            score=min(100, 40 + passive.wayback.snapshot_count // 10),
            weight=0.4,
            evidence=[
                f"{passive.wayback.snapshot_count} archived snapshots "
                "— larger public footprint amplifies reputational loss"
            ],
        ))

    return _factor_from_signals(
        signals,
        notes="Higher Loss Magnitude means a successful attack would have bigger impact.",
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def compute_fair_signals(
    result: DomainResult,
    *,
    scan_mode: str = "full",
) -> FAIRSignals:
    """Derive FAIR-aligned risk signals from a populated ``DomainResult``.

    ``scan_mode`` should be one of: ``passive``, ``lighttouch``,
    ``standard``, ``full`` — it controls the ``confidence`` field and is
    echoed on the output for downstream consumers.
    """
    try:
        tef = _build_threat_event_frequency(result)
        vuln = _build_vulnerability(result)
        control = _build_control_strength(result)
        loss_mag = _build_loss_magnitude(result)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("FAIR signal computation failed for %s: %s", result.target, exc)
        return FAIRSignals(scan_mode=scan_mode, confidence="low")

    # Derived: LEF = TEF × Vulnerability, attenuated by Control Strength.
    # A control_strength of 100 halves the LEF; 0 leaves it untouched.
    tef_n = _neutral(tef)
    vuln_n = _neutral(vuln)
    ctrl_n = _neutral(control)
    raw_lef = (tef_n * vuln_n) / 100.0
    attenuated_lef = raw_lef * (1.0 - ctrl_n / 200.0)
    lef = max(0, min(100, int(round(attenuated_lef))))

    # Overall risk = LEF × Loss Magnitude.
    lm_n = _neutral(loss_mag)
    overall = max(0, min(100, int(round(lef * lm_n / 100.0))))

    if overall >= 75:
        tier = "critical"
    elif overall >= 50:
        tier = "high"
    elif overall >= 25:
        tier = "medium"
    else:
        tier = "low"

    return FAIRSignals(
        threat_event_frequency=tef,
        vulnerability=vuln,
        control_strength=control,
        loss_magnitude=loss_mag,
        loss_event_frequency=lef,
        overall_risk=overall,
        risk_tier=tier,
        confidence=_confidence_for_mode(scan_mode),
        scan_mode=scan_mode,
    )


__all__ = ["compute_fair_signals"]
