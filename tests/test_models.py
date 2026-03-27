"""Tests for Pydantic data models."""

import pytest
from pydantic import ValidationError

from src.models import ScanRequest, ScanResponse, SecretFinding, DomainResult


class TestScanRequest:
    def test_minimal_request(self):
        req = ScanRequest(targets=["https://example.com"])
        assert req.targets == ["https://example.com"]
        assert req.follow_redirects is True
        assert req.render_js is True
        assert req.max_depth == 2

    def test_empty_targets_rejected(self):
        with pytest.raises(ValidationError):
            ScanRequest(targets=[])

    def test_max_depth_bounds(self):
        with pytest.raises(ValidationError):
            ScanRequest(targets=["https://example.com"], max_depth=10)

    def test_custom_options(self):
        req = ScanRequest(
            targets=["https://a.com", "https://b.com"],
            render_js=False,
            max_depth=0,
            check_breaches=False,
            timeout=60,
        )
        assert len(req.targets) == 2
        assert req.render_js is False
        assert req.max_depth == 0


class TestScanResponse:
    def test_defaults(self):
        resp = ScanResponse(scan_id="abc123")
        assert resp.scan_id == "abc123"
        assert resp.status == "completed"
        assert resp.results == []


class TestSecretFinding:
    def test_creation(self):
        finding = SecretFinding(
            secret_type="aws_access_key",
            matched_pattern="aws_access_key_id",
            value_preview="AKIA...MPLE",
            location="script",
        )
        assert finding.severity == "high"


class TestDomainResult:
    def test_defaults(self):
        result = DomainResult(target="https://example.com")
        assert result.pages_scanned == 0
        assert result.pages == []
        assert result.breaches == []
