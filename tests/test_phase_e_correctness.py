"""Phase E correctness — domain aggregation (spec Test 8).

The scanner's build_board_report already aggregates with worst-case/dedup and
never overwrites the root with the last subdomain (the overwrite bug is on the
Xano side). These tests lock that behaviour in and cover the new asset_summary.
"""

from __future__ import annotations

from src.board_report import build_board_report
from src.models import (
    AssetClassification,
    DomainResult,
    DomainSummary,
    EASMReport,
    FindingClassification,
    FindingOwner,
    PrioritizedFinding,
    RiskAssessmentGroup,
)


def _result(target, grade="A", asset_type="website", findings=None):
    easm = EASMReport(
        overall_grade=grade,
        prioritized_findings=findings or [],
        asset_classification=AssetClassification(hostname=target, asset_type=asset_type),
        confirmed_issues=sum(1 for f in (findings or [])
                             if f.classification == FindingClassification.confirmed_issue),
        total_findings=len(findings or []),
    )
    return DomainResult(
        target=target,
        summary=DomainSummary(),
        risk_assessment=RiskAssessmentGroup(easm_report=easm),
    )


def _finding(fid, sev="high"):
    return PrioritizedFinding(
        id=fid, title=fid, category="x", severity=sev,
        classification=FindingClassification.confirmed_issue, owner=FindingOwner.customer,
    )


class TestDomainAggregation:
    def test_root_not_overwritten_by_subdomain(self):
        results = [_result("dnait.ie", grade="B")]
        results += [_result(f"sub{i}.dnait.ie", grade="D") for i in range(18)]
        report = build_board_report("dnait.ie", results)
        assert report.root_domain == "dnait.ie"
        assert report.subdomains_scanned == 19
        # Every asset retains its own row.
        assert len(report.subdomain_rows) == 19
        targets = {row.target for row in report.subdomain_rows}
        assert "dnait.ie" in targets

    def test_domain_wide_findings_deduped(self):
        shared = _finding("missing_hsts")
        results = [
            _result("dnait.ie", findings=[shared]),
            _result("www.dnait.ie", findings=[shared]),
            _result("shop.dnait.ie", findings=[shared]),
        ]
        report = build_board_report("dnait.ie", results)
        hsts = [bf for bf in report.top_findings if bf.finding.id == "missing_hsts"]
        assert len(hsts) == 1                       # deduped to one
        assert len(hsts[0].affected_subdomains) == 3  # but tracks all hosts

    def test_asset_summary_counts_by_type(self):
        results = [
            _result("dnait.ie", asset_type="website"),
            _result("autodiscover.dnait.ie", asset_type="autodiscover_service"),
            _result("mail.dnait.ie", asset_type="mail_service"),
            _result("dead.dnait.ie", asset_type="unresolved"),
        ]
        report = build_board_report("dnait.ie", results)
        s = report.asset_summary
        assert s["total_assets"] == 4
        assert s["website"] == 1
        assert s["autodiscover_service"] == 1
        assert s["mail_service"] == 1
        assert s["unresolved"] == 1
        assert s["active"] == 3
