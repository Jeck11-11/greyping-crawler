"""Central signal-eligibility gate, scan-profile authority, and the schema-2.0
candidate-signal evaluation section.

The scanner is responsible for *evidence* and *candidate* signals only. It must
not be the authoritative source for FAIR weights, category scores or loss
modelling — those are computed downstream (Xano). This module:

* ``is_evidence_risk_eligible`` — one gate every risk-bearing signal passes.
* ``resolve_scan_profile`` — builds the single authoritative ``ScanProfile``.
* ``report_confidence_for`` — per-dimension confidence derived from coverage.
* ``build_signal_evaluation`` — buckets computed FAIR signals into candidate /
  informational / excluded lists with reasons.
"""

from __future__ import annotations

from typing import Any

from .models import (
    CandidateSignal,
    EvidenceRef,
    FAIRFactor,
    FAIRSignal,
    FAIRSignals,
    ReportConfidence,
    ScanProfile,
    SignalEvaluation,
)

# Statuses that must never be treated as a negative/clean result.
_NON_NEGATIVE_STATUSES = frozenset({"unknown", "scan_failed", "not_assessed"})
# Statuses that carry no risk contribution by design.
_NON_RISK_STATUSES = frozenset(
    {"informational", "not_observed", "not_applicable", "unknown", "scan_failed"}
)


# ---------------------------------------------------------------------------
# Central eligibility gate (section 4)
# ---------------------------------------------------------------------------

def is_evidence_risk_eligible(evidence: dict[str, Any] | None) -> dict[str, Any]:
    """Decide whether a technical observation may produce a risk-bearing signal.

    Returns ``{"eligible": bool, "reason": str}``. A finding must NOT bear risk
    when it is informational only, its module was not assessed or failed, the
    finding does not affect the risk score, ownership/public/origin exposure is
    unconfirmed where required, or confidence is below the configured minimum.
    """
    ev = evidence or {}

    if ev.get("affects_risk_score") is False:
        return {"eligible": False, "reason": ev.get("exclusion_reason")
                or "Finding marked affects_risk_score=false"}
    if ev.get("module_failed"):
        return {"eligible": False, "reason": "Required module failed"}
    if ev.get("not_assessed") or ev.get("module_assessed") is False:
        return {"eligible": False, "reason": "Module was not assessed"}
    if ev.get("informational"):
        return {"eligible": False, "reason": "Informational observation only"}
    if ev.get("ownership_required") and not ev.get("ownership_verified", False):
        return {"eligible": False, "reason": "Ownership unverified where ownership is required"}
    if ev.get("public_exposure_required") and not ev.get("public_exposure_confirmed", False):
        return {"eligible": False, "reason": "Public exposure unconfirmed where required"}
    if ev.get("origin_required") and not ev.get("origin_exposure_confirmed", False):
        return {"eligible": False, "reason": ev.get("exclusion_reason")
                or "Origin exposure not confirmed for origin-service finding"}
    conf = ev.get("confidence")
    min_conf = ev.get("min_confidence")
    if conf is not None and min_conf is not None and conf < min_conf:
        return {"eligible": False,
                "reason": f"Confidence {conf} below minimum {min_conf}"}
    return {"eligible": True, "reason": ""}


# ---------------------------------------------------------------------------
# Authoritative scan profile (section 1)
# ---------------------------------------------------------------------------

def resolve_scan_profile(
    *,
    scan_mode: str,
    requested_profile: str = "",
    nuclei_status: str = "skipped",
    modules_completed: list[str] | None = None,
    modules_skipped: list[str] | None = None,
    modules_failed: list[str] | None = None,
) -> ScanProfile:
    """Build the single authoritative ScanProfile for a scan.

    ``scan_mode`` is the orchestrator mode (passive/lighttouch/standard/full).
    Active vulnerability scanning (Nuclei) is *included* only when it was not
    skipped, and *completed* only when it actually finished. The resulting
    profile never claims "full" coverage when active testing was excluded.
    """
    ns = (nuclei_status or "").lower()
    active_included = ns not in ("skipped", "", "not_run", "not_assessed")
    active_completed = ns == "completed"

    mode = (scan_mode or "").lower()
    if mode == "passive":
        profile, coverage = "passive_easm", "passive_only"
    elif mode == "lighttouch":
        profile, coverage = "light_touch", "passive_plus_light_touch"
    elif mode == "standard":
        profile, coverage = "standard_authorized", "active_partial"
    else:  # "full" — active crawl + port/path probing, but Nuclei may be excluded
        if active_completed:
            profile, coverage = "full_authorized", "active_complete"
        else:
            # Active probing happened, but authoritative vuln scanning did not.
            profile, coverage = "passive_easm", "active_partial"

    skipped = list(modules_skipped or [])
    if not active_included and "nuclei" not in skipped:
        skipped.append("nuclei")

    return ScanProfile(
        scan_profile=profile,
        coverage_level=coverage,
        active_vulnerability_scanning_included=active_included,
        active_vulnerability_scanning_completed=active_completed,
        modules_completed=list(modules_completed or []),
        modules_skipped=skipped,
        modules_failed=list(modules_failed or []),
    )


def report_confidence_for(profile: ScanProfile | None) -> ReportConfidence:
    """Per-dimension report confidence derived from scan coverage (section 15)."""
    if profile is None:
        return ReportConfidence()

    cov = profile.coverage_level
    active_done = profile.active_vulnerability_scanning_completed
    failed = bool(profile.modules_failed)

    asset = "high"
    config = "medium" if cov == "passive_only" else "high"

    if active_done:
        vuln = "high"
    elif cov in ("active_partial", "active_complete"):
        # Active probing occurred but authoritative vuln validation was not
        # included — evidence is partial/inferred, so not "high".
        vuln = "medium"
    else:
        vuln = "low"

    business = "low"  # always requires downstream business inputs

    if failed:
        overall = "low"
    elif active_done:
        overall = "high"
    elif cov == "passive_only":
        overall = "low"
    else:
        overall = "medium"

    return ReportConfidence(
        asset_discovery_confidence=asset,
        configuration_assessment_confidence=config,
        vulnerability_assessment_confidence=vuln,
        business_impact_confidence=business,
        overall_report_confidence=overall,
    )


# ---------------------------------------------------------------------------
# Candidate-signal evaluation section (schema 2.0, section 17)
# ---------------------------------------------------------------------------

def _to_candidate(sig: FAIRSignal, category: str) -> CandidateSignal:
    strength = sig.signal_strength if sig.signal_strength is not None else sig.score
    if sig.status in ("unknown", "not_applicable", "scan_failed"):
        strength = None
    return CandidateSignal(
        signal_code=sig.name,
        fair_category=category or sig.fair_category,
        applies=sig.status not in ("not_applicable",),
        status=sig.status,
        signal_strength=strength,
        confidence=sig.confidence,
        severity=sig.severity,
        reason=sig.reason or sig.exclusion_reason,
        evidence=[EvidenceRef(source_module=category, observed_value=e) for e in sig.evidence[:8]],
        source_modules=[category] if category else [],
        risk_eligible=sig.risk_eligible and sig.affects_risk_score
        and sig.status in ("confirmed", "inferred"),
        exclusion_reason=sig.exclusion_reason,
    )


def build_signal_evaluation(
    fair_signals: FAIRSignals | None,
    scan_profile: ScanProfile | None = None,
    *,
    extra_warnings: list[str] | None = None,
) -> SignalEvaluation:
    """Bucket computed FAIR signals into candidate / informational / excluded."""
    evaluation = SignalEvaluation(
        scan_profile=scan_profile,
        report_confidence=report_confidence_for(scan_profile),
        evaluation_warnings=list(extra_warnings or []),
    )
    if fair_signals is None:
        return evaluation

    factors: list[tuple[str, FAIRFactor]] = [
        ("threat_event_frequency", fair_signals.threat_event_frequency),
        ("vulnerability", fair_signals.vulnerability),
        ("control_strength", fair_signals.control_strength),
        ("loss_magnitude", fair_signals.loss_magnitude),
    ]

    for category, factor in factors:
        for sig in factor.signals:
            cand = _to_candidate(sig, category)

            if sig.status == "scan_failed":
                evaluation.excluded_signals.append(cand)
                evaluation.evaluation_warnings.append(
                    f"{sig.name}: required module failed (scan_failed).")
                continue
            if not sig.risk_eligible:
                evaluation.excluded_signals.append(cand)
                continue
            # Controls, informational and non-risk statuses never raise risk.
            if (category == "control_strength"
                    or not sig.affects_risk_score
                    or sig.status in _NON_RISK_STATUSES):
                evaluation.informational_observations.append(cand)
                if sig.status in _NON_NEGATIVE_STATUSES:
                    evaluation.evaluation_warnings.append(
                        f"{sig.name}: {sig.status} — not a negative result.")
                continue
            # confirmed / inferred, risk-eligible, risk-bearing signal.
            evaluation.candidate_signals.append(cand)

    return evaluation


__all__ = [
    "is_evidence_risk_eligible",
    "resolve_scan_profile",
    "report_confidence_for",
    "build_signal_evaluation",
]
