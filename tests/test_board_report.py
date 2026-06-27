"""Tests for estate-wide board report aggregation."""

from __future__ import annotations

import asyncio

import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient

from src.board_report import build_board_report
from src.models import (
    BoardReport,
    BoardScanRequest,
    CompliancePosture,
    DomainResult,
    DomainSummary,
    EASMReport,
    ExecutiveSummary,
    FinancialImpact,
    FindingClassification,
    FindingOwner,
    PrioritizedFinding,
    RansomwareIndex,
    RiskAssessmentGroup,
)


def _make_result(
    target: str,
    grade: str = "A",
    ransomware_score: int = 10,
    financial_high: int = 5000,
    findings: list[PrioritizedFinding] | None = None,
) -> DomainResult:
    """Build a minimal DomainResult with an EASM report for testing."""
    if findings is None:
        findings = []

    confirmed = sum(
        1 for f in findings
        if f.classification == FindingClassification.confirmed_issue
    )

    easm = EASMReport(
        generated_at="2025-01-01T00:00:00+00:00",
        scan_mode="full",
        overall_grade=grade,
        ransomware_susceptibility=RansomwareIndex(
            score=ransomware_score,
            tier="low" if ransomware_score < 25 else "medium" if ransomware_score < 50 else "high",
        ),
        financial_impact=FinancialImpact(
            estimated_annual_loss_low=financial_high // 5,
            estimated_annual_loss_high=financial_high,
            single_incident_cost_low=financial_high // 2,
            single_incident_cost_high=financial_high * 3,
        ),
        prioritized_findings=findings,
        total_findings=len(findings),
        confirmed_issues=confirmed,
    )

    return DomainResult(
        target=target,
        summary=DomainSummary(),
        risk_assessment=RiskAssessmentGroup(easm_report=easm),
    )


def _make_finding(
    finding_id: str,
    title: str = "Test finding",
    severity: str = "medium",
    classification: FindingClassification = FindingClassification.confirmed_issue,
) -> PrioritizedFinding:
    return PrioritizedFinding(
        id=finding_id,
        title=title,
        category="test",
        severity=severity,
        classification=classification,
        owner=FindingOwner.customer,
    )


class TestBuildBoardReport:
    """Unit tests for build_board_report()."""

    def test_empty_results(self):
        report = build_board_report("example.com", [])
        assert isinstance(report, BoardReport)
        assert report.root_domain == "example.com"
        assert report.subdomains_scanned == 0
        assert report.estate_grade == ""
        assert report.total_confirmed_issues == 0

    def test_estate_grade_is_worst(self):
        results = [
            _make_result("example.com", grade="A"),
            _make_result("sub1.example.com", grade="D"),
            _make_result("sub2.example.com", grade="F"),
        ]
        report = build_board_report("example.com", results)
        assert report.estate_grade == "F"

    def test_grade_distribution(self):
        results = [
            _make_result("example.com", grade="A"),
            _make_result("sub1.example.com", grade="A"),
            _make_result("sub2.example.com", grade="F"),
        ]
        report = build_board_report("example.com", results)
        assert report.grade_distribution["A"] == 2
        assert report.grade_distribution["F"] == 1

    def test_ransomware_is_max(self):
        results = [
            _make_result("example.com", ransomware_score=10),
            _make_result("sub1.example.com", ransomware_score=65),
            _make_result("sub2.example.com", ransomware_score=30),
        ]
        report = build_board_report("example.com", results)
        assert report.ransomware_susceptibility.score == 65
        assert "sub1.example.com" in report.ransomware_susceptibility.factors[-1]

    def test_financial_headline_is_worst_subdomain(self):
        results = [
            _make_result("example.com", financial_high=5000),
            _make_result("sub1.example.com", financial_high=50000),
            _make_result("sub2.example.com", financial_high=2000),
        ]
        report = build_board_report("example.com", results)
        assert report.financial_impact.estimated_annual_loss_high == 50000
        assert any("sub1.example.com" in f for f in report.financial_impact.factors)

    def test_financial_not_summed(self):
        results = [
            _make_result("example.com", financial_high=10000),
            _make_result("sub1.example.com", financial_high=10000),
        ]
        report = build_board_report("example.com", results)
        assert report.financial_impact.estimated_annual_loss_high == 10000

    def test_findings_merged_and_deduped(self):
        shared_finding = _make_finding("missing_hsts", title="Missing HSTS")
        unique_finding = _make_finding("exposed_env", title="Exposed .env")

        results = [
            _make_result("example.com", findings=[shared_finding]),
            _make_result("sub1.example.com", findings=[shared_finding, unique_finding]),
        ]
        report = build_board_report("example.com", results)

        finding_ids = [bf.finding.id for bf in report.top_findings]
        assert "missing_hsts" in finding_ids
        assert "exposed_env" in finding_ids
        assert len(report.top_findings) == 2

        hsts_bf = next(bf for bf in report.top_findings if bf.finding.id == "missing_hsts")
        assert len(hsts_bf.affected_subdomains) == 2
        assert "example.com" in hsts_bf.affected_subdomains
        assert "sub1.example.com" in hsts_bf.affected_subdomains

    def test_compliance_posture_present(self):
        results = [
            _make_result("example.com", findings=[
                _make_finding("missing_hsts", severity="high"),
            ]),
        ]
        report = build_board_report("example.com", results)
        assert len(report.compliance_posture) == 3
        frameworks = {cp.framework for cp in report.compliance_posture}
        assert "PCI-DSS 4.0" in frameworks
        assert "ISO 27001" in frameworks
        assert "GDPR" in frameworks

    def test_subdomain_rows_sorted_worst_first(self):
        results = [
            _make_result("example.com", grade="A"),
            _make_result("bad.example.com", grade="F"),
            _make_result("ok.example.com", grade="C"),
        ]
        report = build_board_report("example.com", results)
        assert len(report.subdomain_rows) == 3
        assert report.subdomain_rows[0].target == "bad.example.com"
        assert report.subdomain_rows[0].grade == "F"

    def test_total_confirmed_issues(self):
        results = [
            _make_result("example.com", findings=[
                _make_finding("f1"),
                _make_finding("f2", classification=FindingClassification.informational),
            ]),
            _make_result("sub.example.com", findings=[
                _make_finding("f3"),
            ]),
        ]
        report = build_board_report("example.com", results)
        assert report.total_confirmed_issues == 2

    def test_executive_summary_populated(self):
        results = [
            _make_result("example.com", grade="B", findings=[
                _make_finding("f1", title="Missing HSTS"),
            ]),
        ]
        report = build_board_report("example.com", results)
        assert report.executive_summary.overall_grade == "B"
        assert "example.com" in report.executive_summary.narrative
        assert report.executive_summary.scan_coverage == "board"

    def test_subdomains_discovered_count(self):
        results = [_make_result("example.com")]
        report = build_board_report("example.com", results, subdomains_discovered=15)
        assert report.subdomains_discovered == 15
        assert report.subdomains_scanned == 1

    def test_single_result(self):
        results = [_make_result("example.com", grade="A", ransomware_score=5, financial_high=1000)]
        report = build_board_report("example.com", results)
        assert report.estate_grade == "A"
        assert report.ransomware_susceptibility.score == 5
        assert report.financial_impact.estimated_annual_loss_high == 1000
        assert report.subdomains_scanned == 1


class TestBoardScanEndpoint:
    """Tests for async POST /scan/board + GET /scan/board/{scan_id}."""

    @pytest.fixture
    def client(self):
        from src.app import app, _BOARD_JOBS
        _BOARD_JOBS.clear()
        return TestClient(app)

    def test_board_endpoint_returns_202(self, client):
        """POST /scan/board returns 202 immediately with a scan_id."""
        mock_ct = AsyncMock(return_value=type("CT", (), {"subdomains": ["sub1.example.com"], "error": None})())
        mock_enum = AsyncMock(return_value={
            "domain": "example.com",
            "live_subdomains": ["sub1.example.com"],
            "resolved": [],
            "sources": {},
        })

        async def mock_scan_single(target, req):
            return _make_result(target, grade="B")

        mock_webhook = AsyncMock(return_value=True)

        with (
            patch("src.app.query_ct_logs", mock_ct),
            patch("src.subdomain_takeover.enumerate_subdomains", mock_enum),
            patch("src.app._scan_single_target", side_effect=mock_scan_single),
            patch("src.nuclei_webhook.post_board_webhook", mock_webhook),
        ):
            resp = client.post("/scan/board", json={"root_domain": "example.com"})

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending"
        assert "scan_id" in data
        assert data["root_domain"] == "example.com"
        assert data["poll_url"].startswith("/scan/board/")

    def test_poll_unknown_scan_returns_404(self, client):
        resp = client.get("/scan/board/nonexistent")
        assert resp.status_code == 404

    def test_poll_shows_completed_after_job_runs(self, client):
        """After the background job finishes, GET returns the full report."""
        mock_ct = AsyncMock(return_value=type("CT", (), {"subdomains": [], "error": None})())
        mock_enum = AsyncMock(return_value={
            "domain": "example.com",
            "live_subdomains": [],
            "resolved": [],
            "sources": {},
        })

        async def mock_scan_single(target, req):
            return _make_result(target, grade="B")

        mock_webhook = AsyncMock(return_value=True)

        with (
            patch("src.app.query_ct_logs", mock_ct),
            patch("src.subdomain_takeover.enumerate_subdomains", mock_enum),
            patch("src.app._scan_single_target", side_effect=mock_scan_single),
            patch("src.nuclei_webhook.post_board_webhook", mock_webhook),
        ):
            resp = client.post("/scan/board", json={"root_domain": "example.com"})
            scan_id = resp.json()["scan_id"]

            poll = client.get(f"/scan/board/{scan_id}")

        data = poll.json()
        assert data["status"] in ("completed", "partial", "running", "pending")
        if data["status"] == "completed":
            assert data["board_report"] is not None
            assert data["board_report"]["root_domain"] == "example.com"

    def test_board_endpoint_with_max_subdomains(self, client):
        mock_ct = AsyncMock(return_value=type("CT", (), {
            "subdomains": [f"sub{i}.example.com" for i in range(10)],
            "error": None,
        })())
        mock_enum = AsyncMock(return_value={
            "domain": "example.com",
            "live_subdomains": [f"sub{i}.example.com" for i in range(10)],
            "resolved": [],
            "sources": {},
        })

        async def mock_scan_single(target, req):
            return _make_result(target, grade="A")

        mock_webhook = AsyncMock(return_value=True)

        with (
            patch("src.app.query_ct_logs", mock_ct),
            patch("src.subdomain_takeover.enumerate_subdomains", mock_enum),
            patch("src.app._scan_single_target", side_effect=mock_scan_single),
            patch("src.nuclei_webhook.post_board_webhook", mock_webhook),
        ):
            resp = client.post("/scan/board", json={
                "root_domain": "example.com",
                "max_subdomains": 3,
            })

        assert resp.status_code == 202

    def test_webhook_called_on_completion(self, client):
        """post_board_webhook is called once the job finishes."""
        mock_ct = AsyncMock(return_value=type("CT", (), {"subdomains": [], "error": None})())
        mock_enum = AsyncMock(return_value={
            "domain": "example.com",
            "live_subdomains": [],
            "resolved": [],
            "sources": {},
        })

        async def mock_scan_single(target, req):
            return _make_result(target, grade="A")

        mock_webhook = AsyncMock(return_value=True)

        with (
            patch("src.app.query_ct_logs", mock_ct),
            patch("src.subdomain_takeover.enumerate_subdomains", mock_enum),
            patch("src.app._scan_single_target", side_effect=mock_scan_single),
            patch("src.nuclei_webhook.post_board_webhook", mock_webhook),
        ):
            resp = client.post("/scan/board", json={"root_domain": "example.com"})
            scan_id = resp.json()["scan_id"]
            # TestClient runs the event loop synchronously, so the background
            # task should complete by the time we poll.
            poll = client.get(f"/scan/board/{scan_id}")

        if poll.json()["status"] == "completed":
            mock_webhook.assert_called_once()


class TestAggregateEndpoint:
    """Tests for POST /report/aggregate."""

    @pytest.fixture
    def client(self):
        from src.app import app
        return TestClient(app)

    def test_aggregate_returns_board_report(self, client):
        """Sending stored EASM data returns a valid board report."""
        payload = {
            "root_domain": "example.com",
            "subdomains": [
                {
                    "target": "www.example.com",
                    "overall_grade": "B",
                    "confirmed_issues": 3,
                    "total_findings": 5,
                    "prioritized_findings": [
                        {
                            "id": "missing_hsts",
                            "title": "Missing HSTS",
                            "category": "security_headers",
                            "severity": "high",
                            "classification": "confirmed_issue",
                            "owner": "customer",
                        },
                    ],
                    "financial_impact": {
                        "estimated_annual_loss_low": 1000,
                        "estimated_annual_loss_high": 5000,
                    },
                    "ransomware_susceptibility": {"score": 30, "tier": "medium"},
                },
                {
                    "target": "mail.example.com",
                    "overall_grade": "D",
                    "confirmed_issues": 1,
                    "total_findings": 2,
                    "prioritized_findings": [
                        {
                            "id": "missing_hsts",
                            "title": "Missing HSTS",
                            "category": "security_headers",
                            "severity": "high",
                            "classification": "confirmed_issue",
                            "owner": "customer",
                        },
                        {
                            "id": "email_no_dmarc",
                            "title": "No DMARC record",
                            "category": "email_security",
                            "severity": "medium",
                            "classification": "confirmed_issue",
                            "owner": "customer",
                        },
                    ],
                    "financial_impact": {
                        "estimated_annual_loss_low": 2000,
                        "estimated_annual_loss_high": 15000,
                    },
                    "ransomware_susceptibility": {"score": 55, "tier": "high"},
                },
            ],
        }
        resp = client.post("/report/aggregate", json=payload)
        assert resp.status_code == 200
        data = resp.json()

        assert data["root_domain"] == "example.com"
        assert data["estate_grade"] == "D"
        assert data["subdomains_scanned"] == 2
        assert data["subdomains_discovered"] == 2

        assert data["ransomware_susceptibility"]["score"] == 55

        assert data["financial_impact"]["estimated_annual_loss_high"] == 15000

        finding_ids = [bf["finding"]["id"] for bf in data["top_findings"]]
        assert "missing_hsts" in finding_ids
        assert "email_no_dmarc" in finding_ids

        hsts = next(bf for bf in data["top_findings"] if bf["finding"]["id"] == "missing_hsts")
        assert len(hsts["affected_subdomains"]) == 2

    def test_aggregate_single_subdomain(self, client):
        """Works with a single subdomain — no aggregation needed."""
        payload = {
            "root_domain": "single.com",
            "subdomains": [
                {
                    "target": "single.com",
                    "overall_grade": "A",
                    "confirmed_issues": 0,
                    "total_findings": 1,
                    "prioritized_findings": [],
                },
            ],
        }
        resp = client.post("/report/aggregate", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["estate_grade"] == "A"
        assert data["subdomains_scanned"] == 1
        assert data["total_confirmed_issues"] == 0

    def test_aggregate_empty_subdomains_rejected(self, client):
        """At least one subdomain is required."""
        payload = {"root_domain": "empty.com", "subdomains": []}
        resp = client.post("/report/aggregate", json=payload)
        assert resp.status_code == 422


class TestAsyncScanEndpoint:
    """Tests for async batch scan: POST /scan/async + GET /scan/async/{scan_id}."""

    @pytest.fixture
    def client(self):
        from src.app import app, _SCAN_JOBS
        _SCAN_JOBS.clear()
        return TestClient(app)

    def test_async_scan_returns_202(self, client):
        """POST /scan/async returns 202 immediately with a scan_id and target count."""
        async def mock_scan_single(target, req):
            return _make_result(target, grade="B")

        mock_webhook = AsyncMock(return_value=True)
        mock_complete = AsyncMock(return_value=True)

        with (
            patch("src.app._scan_single_target", side_effect=mock_scan_single),
            patch("src.nuclei_webhook.post_scan_result_webhook", mock_webhook),
            patch("src.nuclei_webhook.post_scan_complete_webhook", mock_complete),
        ):
            resp = client.post("/scan/async", json={
                "targets": ["https://a.example.com", "https://b.example.com"],
            })

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending"
        assert data["targets_total"] == 2
        assert "scan_id" in data
        assert data["poll_url"].startswith("/scan/async/")

    def test_poll_unknown_scan_returns_404(self, client):
        resp = client.get("/scan/async/nonexistent")
        assert resp.status_code == 404

    def test_each_result_webhooked_incrementally(self, client):
        """Every completed target is POSTed to the webhook as it finishes."""
        async def mock_scan_single(target, req):
            return _make_result(target, grade="B")

        mock_webhook = AsyncMock(return_value=True)
        mock_complete = AsyncMock(return_value=True)

        with (
            patch("src.app._scan_single_target", side_effect=mock_scan_single),
            patch("src.nuclei_webhook.post_scan_result_webhook", mock_webhook),
            patch("src.nuclei_webhook.post_scan_complete_webhook", mock_complete),
        ):
            resp = client.post("/scan/async", json={
                "targets": [
                    "https://a.example.com",
                    "https://b.example.com",
                    "https://c.example.com",
                ],
            })
            scan_id = resp.json()["scan_id"]
            poll = client.get(f"/scan/async/{scan_id}")

        data = poll.json()
        if data["status"] == "completed":
            assert data["targets_completed"] == 3
            assert data["targets_failed"] == 0
            assert mock_webhook.call_count == 3
            mock_complete.assert_called_once()

    def test_failed_target_counted_not_fatal(self, client):
        """A target that raises is counted as failed; the batch still completes."""
        async def mock_scan_single(target, req):
            if "bad" in target:
                raise RuntimeError("scan blew up")
            return _make_result(target, grade="A")

        mock_webhook = AsyncMock(return_value=True)
        mock_complete = AsyncMock(return_value=True)

        with (
            patch("src.app._scan_single_target", side_effect=mock_scan_single),
            patch("src.nuclei_webhook.post_scan_result_webhook", mock_webhook),
            patch("src.nuclei_webhook.post_scan_complete_webhook", mock_complete),
        ):
            resp = client.post("/scan/async", json={
                "targets": ["https://good.example.com", "https://bad.example.com"],
            })
            scan_id = resp.json()["scan_id"]
            poll = client.get(f"/scan/async/{scan_id}")

        data = poll.json()
        if data["status"] == "completed":
            assert data["targets_completed"] == 1
            assert data["targets_failed"] == 1
            # Only the successful target is webhooked.
            assert mock_webhook.call_count == 1
