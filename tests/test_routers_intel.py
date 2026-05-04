"""Tests for /recon/breaches and /recon/email-validation."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.app import app
from src.models import BreachRecord, EmailValidationResult


client = TestClient(app)


class TestReconBreaches:
    @patch("src.routers.intel.check_breaches", new_callable=AsyncMock)
    def test_breaches_normalises_and_passes_domain(self, mock_check):
        mock_check.return_value = [
            BreachRecord(
                source="HIBP",
                breach_name="AcmeLeak",
                domain="example.com",
                breach_date="2022-01-01",
                data_types=["email", "password"],
            ),
        ]
        resp = client.post(
            "/recon/breaches",
            json={
                "targets": ["https://example.com"],
                "emails": ["user@example.com"],
            },
        )
        assert resp.status_code == 200
        body = resp.json()[0]
        assert body["breaches"][0]["breach_name"] == "AcmeLeak"
        # Domain-only (without scheme / www) is what gets passed to HIBP
        args, _ = mock_check.call_args
        assert args[0] == "example.com"
        assert args[1] == ["user@example.com"]

    @patch("src.routers.intel.check_breaches", new_callable=AsyncMock)
    def test_breaches_records_errors_without_failing_whole_batch(self, mock_check):
        mock_check.side_effect = [RuntimeError("rate-limited"), []]
        resp = client.post(
            "/recon/breaches",
            json={"targets": ["https://a.com", "https://b.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["error"] == "rate-limited"
        assert body[1]["breaches"] == []


class TestReconEmailValidation:
    @patch("src.routers.intel.validate_email", new_callable=AsyncMock)
    def test_email_validation_returns_result(self, mock_validate):
        mock_validate.return_value = {
            "email": "test@example.com",
            "valid": True,
            "disposable": False,
            "role_account": False,
            "free_provider": True,
            "details": {},
        }
        resp = client.post(
            "/recon/email-validation",
            json={"emails": ["test@example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["email"] == "test@example.com"
        assert body[0]["valid"] is True
        assert body[0]["disposable"] is False
        assert body[0]["role_account"] is False
        assert body[0]["free_provider"] is True

    @patch("src.routers.intel.validate_email", new_callable=AsyncMock)
    def test_email_validation_handles_c99_failure(self, mock_validate):
        mock_validate.side_effect = RuntimeError("C99 API error")
        resp = client.post(
            "/recon/email-validation",
            json={"emails": ["test@example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["email"] == "test@example.com"
        assert body[0]["error"] is not None
        assert "C99 API error" in body[0]["error"]

    @patch("src.routers.intel.validate_email", new_callable=AsyncMock)
    def test_email_validation_no_api_key(self, mock_validate):
        mock_validate.return_value = None
        resp = client.post(
            "/recon/email-validation",
            json={"emails": ["test@example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["email"] == "test@example.com"
        assert body[0]["error"] is not None
        assert "unavailable" in body[0]["error"].lower()
