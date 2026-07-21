"""Tests for the nuclei background webhook module."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.models import (
    DomainResult,
    NucleiResult,
    NucleiFinding,
    RiskAssessmentGroup,
    VulnerabilitiesGroup,
)
from src.nuclei_webhook import _post_webhook, nuclei_background_scan


@pytest.fixture
def sample_domain_result():
    return DomainResult(
        target="https://example.com",
        vulnerabilities=VulnerabilitiesGroup(
            nuclei=NucleiResult(target="https://example.com"),
        ),
    )


class TestPostWebhook:
    @patch("src.nuclei_webhook.XANO_WEBHOOK_URL", "")
    @pytest.mark.asyncio
    async def test_skips_when_no_url(self):
        result = await _post_webhook({"test": "data"})
        assert result is False

    @patch("src.nuclei_webhook.XANO_WEBHOOK_URL", "https://xano.test/webhook")
    @patch("src.nuclei_webhook.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_posts_successfully(self, mock_client_cls):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await _post_webhook({"scan_id": "abc", "target": "example.com"})
        assert result is True
        mock_client.post.assert_called_once()

    @patch("src.nuclei_webhook.XANO_WEBHOOK_URL", "https://xano.test/webhook")
    @patch("src.nuclei_webhook._BACKOFF_BASE", 0.01)
    @patch("src.nuclei_webhook.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_retries_on_failure(self, mock_client_cls):
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("connection reset")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await _post_webhook({"target": "fail.com"})
        assert result is False
        assert mock_client.post.call_count == 3

    @patch("src.nuclei_webhook.XANO_WEBHOOK_URL", "https://xano.test/webhook")
    @patch("src.nuclei_webhook._BACKOFF_BASE", 0.01)
    @patch("src.nuclei_webhook.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_retries_on_429(self, mock_client_cls):
        rate_limited = MagicMock()
        rate_limited.status_code = 429
        rate_limited.headers = {"Retry-After": "0"}
        ok_resp = MagicMock()
        ok_resp.status_code = 200
        ok_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post.side_effect = [rate_limited, ok_resp]
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        result = await _post_webhook({"target": "rate-limited.com"})
        assert result is True
        assert mock_client.post.call_count == 2


class TestNucleiBackgroundScan:
    @patch("src.nuclei_webhook._post_webhook", new_callable=AsyncMock)
    @patch("src.nuclei_webhook.run_nuclei_scan", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_runs_nuclei_and_posts(self, mock_nuclei, mock_webhook, sample_domain_result):
        mock_nuclei.return_value = NucleiResult(
            target="https://example.com",
            findings=[
                NucleiFinding(
                    template_id="cve-2021-1234",
                    name="Test Vuln",
                    severity="high",
                ),
            ],
            templates_run=50,
            scan_duration_seconds=12.5,
        )
        mock_webhook.return_value = True

        await nuclei_background_scan("scan123", [sample_domain_result])

        mock_nuclei.assert_called_once_with(["https://example.com"])
        mock_webhook.assert_called_once()

        payload = mock_webhook.call_args[0][0]
        assert payload["scan_id"] == "scan123"
        assert payload["target"] == "https://example.com"
        assert payload["nuclei_status"] == "completed"
        assert "result" in payload
        result_data = payload["result"]
        assert result_data["target"] == "https://example.com"
        assert result_data["risk_assessment"]["easm_report"] is not None

    @patch("src.nuclei_webhook._post_webhook", new_callable=AsyncMock)
    @patch("src.nuclei_webhook.run_nuclei_scan", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_nuclei_error_sets_status(self, mock_nuclei, mock_webhook, sample_domain_result):
        mock_nuclei.return_value = NucleiResult(
            target="https://example.com",
            error="timeout after 300s",
        )
        mock_webhook.return_value = True

        await nuclei_background_scan("scan456", [sample_domain_result])

        payload = mock_webhook.call_args[0][0]
        assert payload["nuclei_status"] == "error"

    @patch("src.nuclei_webhook._post_webhook", new_callable=AsyncMock)
    @patch("src.nuclei_webhook.run_nuclei_scan", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_rebuilds_easm_report(self, mock_nuclei, mock_webhook, sample_domain_result):
        mock_nuclei.return_value = NucleiResult(
            target="https://example.com",
            findings=[
                NucleiFinding(template_id="xss-1", name="XSS", severity="high"),
            ],
        )
        mock_webhook.return_value = True

        await nuclei_background_scan("scan789", [sample_domain_result])

        payload = mock_webhook.call_args[0][0]
        easm = payload["result"]["risk_assessment"]["easm_report"]
        assert easm is not None
        assert "overall_grade" in easm

    @patch("src.nuclei_webhook._post_webhook", new_callable=AsyncMock)
    @patch("src.nuclei_webhook.run_nuclei_scan", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_survives_nuclei_exception(self, mock_nuclei, mock_webhook, sample_domain_result):
        mock_nuclei.side_effect = RuntimeError("unexpected crash")
        mock_webhook.return_value = True

        await nuclei_background_scan("scan_crash", [sample_domain_result])
        mock_webhook.assert_not_called()
