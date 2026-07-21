"""Estate-wide board report — aggregates per-subdomain EASM reports."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from .easm_report import grade_to_score, sort_findings, compute_compliance_posture, RISK_TO_GRADE
from .models import (
    BoardFinding,
    BoardReport,
    CompliancePosture,
    DomainResult,
    ExecutiveSummary,
    FinancialImpact,
    PrioritizedFinding,
    RansomwareIndex,
    SubdomainReportRow,
    FindingClassification,
)

logger = logging.getLogger("osint_api")


def _worst_grade(grades: list[str]) -> str:
    """Return the worst (lowest-scoring) grade from a list."""
    if not grades:
        return ""
    return min(grades, key=grade_to_score)


def _grade_distribution(grades: list[str]) -> dict[str, int]:
    """Build a histogram of grade counts, preserving +/- modifiers."""
    dist: dict[str, int] = {}
    for g in grades:
        key = g if g else "?"
        dist[key] = dist.get(key, 0) + 1
    return dist


def _build_subdomain_rows(results: list[DomainResult]) -> list[SubdomainReportRow]:
    """Build per-subdomain summary rows, sorted worst-first."""
    rows: list[SubdomainReportRow] = []
    for r in results:
        easm = r.easm_report
        if not easm:
            rows.append(SubdomainReportRow(target=r.target))
            continue

        top_concern = ""
        for f in easm.prioritized_findings:
            if f.classification == FindingClassification.confirmed_issue:
                top_concern = f.title
                break

        rows.append(SubdomainReportRow(
            target=r.target,
            grade=easm.overall_grade,
            ransomware_score=easm.ransomware_susceptibility.score,
            financial_low=easm.financial_impact.estimated_annual_loss_low,
            financial_high=easm.financial_impact.estimated_annual_loss_high,
            confirmed_issues=easm.confirmed_issues,
            total_findings=easm.total_findings,
            top_concern=top_concern,
        ))

    rows.sort(key=lambda row: grade_to_score(row.grade))
    return rows


def _merge_findings(
    results: list[DomainResult],
) -> list[BoardFinding]:
    """Merge and deduplicate findings across all subdomain EASM reports."""
    seen: dict[tuple[str, str], BoardFinding] = {}

    for r in results:
        easm = r.easm_report
        if not easm:
            continue
        target = r.target
        for f in easm.prioritized_findings:
            key = (f.id, f.fingerprint)
            if key in seen:
                if target not in seen[key].affected_subdomains:
                    seen[key].affected_subdomains.append(target)
            else:
                seen[key] = BoardFinding(
                    finding=f,
                    affected_subdomains=[target],
                )

    sorted_board = sorted(
        seen.values(),
        key=lambda bf: (
            grade_to_score(bf.finding.severity) if bf.finding.severity in ("critical", "high", "medium", "low", "info") else 50,
            len(bf.affected_subdomains),
        ),
    )

    plain_findings = [bf.finding for bf in seen.values()]
    re_sorted = sort_findings(plain_findings)
    id_order = {(f.id, f.fingerprint): i for i, f in enumerate(re_sorted)}
    sorted_board = sorted(seen.values(), key=lambda bf: id_order.get((bf.finding.id, bf.finding.fingerprint), 999))

    return sorted_board


def _aggregate_ransomware(results: list[DomainResult]) -> RansomwareIndex:
    """Pick the worst ransomware index across all subdomains."""
    worst_score = 0
    worst_ri = RansomwareIndex()
    for r in results:
        easm = r.easm_report
        if not easm:
            continue
        ri = easm.ransomware_susceptibility
        if ri.score > worst_score:
            worst_score = ri.score
            worst_ri = RansomwareIndex(
                score=ri.score,
                tier=ri.tier,
                factors=ri.factors + [f"Driven by {r.target}"],
                mitigations=ri.mitigations,
            )
    return worst_ri


def _aggregate_financial(
    results: list[DomainResult],
) -> FinancialImpact:
    """Headline financial impact = worst single subdomain."""
    worst = FinancialImpact()
    worst_high = 0
    for r in results:
        easm = r.easm_report
        if not easm:
            continue
        fi = easm.financial_impact
        if fi.estimated_annual_loss_high > worst_high:
            worst_high = fi.estimated_annual_loss_high
            worst = FinancialImpact(
                estimated_annual_loss_low=fi.estimated_annual_loss_low,
                estimated_annual_loss_high=fi.estimated_annual_loss_high,
                single_incident_cost_low=fi.single_incident_cost_low,
                single_incident_cost_high=fi.single_incident_cost_high,
                methodology=fi.methodology,
                factors=fi.factors + [
                    f"Estate headline driven by worst subdomain: {r.target}. "
                    "Per-subdomain breakdown available in financial_breakdown."
                ],
            )
    return worst


def _build_estate_summary(
    root_domain: str,
    results: list[DomainResult],
    estate_grade: str,
    board_findings: list[BoardFinding],
    total_confirmed: int,
    ransomware: RansomwareIndex,
    financial: FinancialImpact,
) -> ExecutiveSummary:
    """Build an estate-wide executive summary."""
    scanned = len(results)

    worst_assets = []
    for r in sorted(results, key=lambda r: grade_to_score(r.easm_report.overall_grade if r.easm_report else "")):
        if r.easm_report and r.easm_report.overall_grade:
            worst_assets.append(f"{r.target} ({r.easm_report.overall_grade})")
        if len(worst_assets) >= 3:
            break

    top_risks = []
    for bf in board_findings[:3]:
        top_risks.append(f"{bf.finding.title} (affects {len(bf.affected_subdomains)} asset(s))")

    narrative_parts = [
        f"Estate scan of {root_domain}: {scanned} subdomains scanned, estate grade {estate_grade}.",
    ]
    if total_confirmed:
        narrative_parts.append(f"{total_confirmed} confirmed issues identified across the estate.")
    if worst_assets:
        narrative_parts.append(f"Weakest assets: {', '.join(worst_assets)}.")

    if financial.estimated_annual_loss_high > 0:
        hi = financial.estimated_annual_loss_high
        if hi >= 1_000_000:
            narrative_parts.append(f"Worst-case annual exposure: ${hi / 1_000_000:.1f}M.")
        elif hi >= 10_000:
            narrative_parts.append(f"Worst-case annual exposure: ${round(hi / 1000)}K.")
        else:
            narrative_parts.append(f"Worst-case annual exposure: ${hi:,}.")

    risk_posture = "Low"
    gs = grade_to_score(estate_grade)
    if gs <= 25:
        risk_posture = "Critical"
    elif gs <= 50:
        risk_posture = "High"
    elif gs <= 70:
        risk_posture = "Moderate"

    key_positives = []
    key_concerns = []
    for bf in board_findings:
        f = bf.finding
        if f.classification == FindingClassification.confirmed_issue and len(key_concerns) < 3:
            key_concerns.append(f.title)
    if ransomware.score < 25:
        key_positives.append("Low ransomware susceptibility across estate.")
    if total_confirmed == 0:
        key_positives.append("No confirmed security issues found.")

    recommendations = []
    for bf in board_findings[:3]:
        if bf.finding.recommended_action:
            recommendations.append(bf.finding.recommended_action)

    return ExecutiveSummary(
        risk_posture=risk_posture,
        narrative=" ".join(narrative_parts),
        key_positives=key_positives[:3],
        key_concerns=key_concerns[:3],
        scan_coverage="board",
        overall_grade=estate_grade,
        grades={"estate": estate_grade},
        top_risks=top_risks,
        recommendations=recommendations,
    )


def _build_asset_summary(results: list[DomainResult]) -> dict[str, int]:
    """Count assets by classification type/status across the estate."""
    summary: dict[str, int] = {"total_assets": len(results)}
    active = 0
    for r in results:
        easm = r.easm_report
        atype = "unknown"
        if easm and easm.asset_classification:
            atype = easm.asset_classification.asset_type or "unknown"
        summary[atype] = summary.get(atype, 0) + 1
        if atype not in ("unresolved", "inactive", "parked_domain"):
            active += 1
    summary["active"] = active
    summary["unresolved"] = summary.get("unresolved", 0)
    return summary


def build_board_report(
    root_domain: str,
    results: list[DomainResult],
    *,
    subdomains_discovered: int = 0,
) -> BoardReport:
    """Aggregate per-subdomain EASM reports into one estate-wide board report."""
    try:
        now = datetime.now(timezone.utc).isoformat()

        if not results:
            return BoardReport(
                root_domain=root_domain,
                generated_at=now,
            )

        grades = []
        for r in results:
            easm = r.easm_report
            if easm and easm.overall_grade:
                grades.append(easm.overall_grade)

        estate_grade = _worst_grade(grades)
        dist = _grade_distribution(grades)

        subdomain_rows = _build_subdomain_rows(results)
        board_findings = _merge_findings(results)
        ransomware = _aggregate_ransomware(results)
        financial = _aggregate_financial(results)

        # Count DISTINCT confirmed issues across the estate (deduped), so the
        # headline matches the top_findings list. The per-subdomain instance
        # counts remain available in subdomain_rows[].confirmed_issues.
        total_confirmed = sum(
            1 for bf in board_findings
            if bf.finding.classification == FindingClassification.confirmed_issue
        )

        all_plain_findings = [bf.finding for bf in board_findings]
        compliance = compute_compliance_posture(all_plain_findings)

        framework_counts: dict[str, int] = {}
        for f in all_plain_findings:
            for tag in f.compliance:
                framework = tag.split(" ")[0]
                framework_counts[framework] = framework_counts.get(framework, 0) + 1

        executive = _build_estate_summary(
            root_domain, results, estate_grade,
            board_findings, total_confirmed, ransomware, financial,
        )

        return BoardReport(
            root_domain=root_domain,
            generated_at=now,
            subdomains_discovered=subdomains_discovered or len(results),
            subdomains_scanned=len(results),
            estate_grade=estate_grade,
            grade_distribution=dist,
            executive_summary=executive,
            ransomware_susceptibility=ransomware,
            financial_impact=financial,
            financial_breakdown=subdomain_rows,
            compliance_posture=compliance,
            compliance_summary=framework_counts,
            top_findings=board_findings,
            subdomain_rows=subdomain_rows,
            asset_summary=_build_asset_summary(results),
            total_confirmed_issues=total_confirmed,
        )
    except Exception as exc:
        logger.warning(
            "Board report generation failed for %s: %s",
            root_domain, exc, exc_info=True,
        )
        return BoardReport(
            root_domain=root_domain,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
