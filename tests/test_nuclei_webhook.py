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
        assert result_data["risk_assessment"]["fair_signals"] is not None

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
    async def test_recomputes_fair_signals(self, mock_nuclei, mock_webhook, sample_domain_result):
        mock_nuclei.return_value = NucleiResult(
            target="https://example.com",
            findings=[
                NucleiFinding(template_id="xss-1", name="XSS", severity="high"),
            ],
        )
        mock_webhook.return_value = True

        await nuclei_background_scan("scan789", [sample_domain_result])

        payload = mock_webhook.call_args[0][0]
        fair = payload["result"]["risk_assessment"]["fair_signals"]
        assert fair is not None
        vuln_names = [s["name"] for s in fair["vulnerability"]["signals"]]
        assert "nuclei_vulnerabilities" in vuln_names

    @patch("src.nuclei_webhook._post_webhook", new_callable=AsyncMock)
    @patch("src.nuclei_webhook.run_nuclei_scan", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_survives_nuclei_exception(self, mock_nuclei, mock_webhook, sample_domain_result):
        mock_nuclei.side_effect = RuntimeError("unexpected crash")
        mock_webhook.return_value = True

        await nuclei_background_scan("scan_crash", [sample_domain_result])
        mock_webhook.assert_not_called()


class TestAggregateScoreSoftening:
    def test_single_critical_below_100(self):
        from src.fair_signals import _aggregate_findings_score
        from src.models import SecretFinding

        items = [
            SecretFinding(
                secret_type="aws_key", matched_pattern="AKIA",
                value_preview="AKIA...", location="script", severity="critical",
            ),
        ]
        score = _aggregate_findings_score(items)
        assert score < 100
        assert score == 85  # int(100 * 0.8) + 0 + 5

    def test_five_criticals_reach_100(self):
        from src.fair_signals import _aggregate_findings_score
        from src.models import SecretFinding

        items = [
            SecretFinding(
                secret_type=f"key_{i}", matched_pattern="AKIA",
                value_preview="AKIA...", location="script", severity="critical",
            )
            for i in range(5)
        ]
        score = _aggregate_findings_score(items)
        assert score == 100  # int(100 * 0.8) + 20 + 5 = 105, capped at 100

    def test_empty_returns_zero(self):
        from src.fair_signals import _aggregate_findings_score
        assert _aggregate_findings_score([]) == 0


class TestDoubleCountingWeights:
    def test_credential_exposure_weight_reduced(self):
        from src.fair_signals import compute_fair_signals
        from src.models import DomainResult, SecurityGroup, SecretFinding

        result = DomainResult(
            target="https://example.com",
            security=SecurityGroup(
                secrets=[
                    SecretFinding(
                        secret_type="api_key", matched_pattern="sk-",
                        value_preview="sk-...", location="js", severity="high",
                    ),
                ],
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        cred_sig = next(
            s for s in signals.loss_magnitude.signals if s.name == "credential_exposure"
        )
        assert cred_sig.weight == 0.8

    def test_brand_impersonation_weight_reduced(self):
        from src.fair_signals import compute_fair_signals
        from src.models import DomainResult, TyposquattingResult, TyposquatCandidate

        result = DomainResult(
            target="https://example.com",
            typosquatting=TyposquattingResult(
                domain="example.com",
                registered_candidates=[
                    TyposquatCandidate(domain="examp1e.com", registered=True),
                ],
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        brand_sig = next(
            s for s in signals.loss_magnitude.signals if s.name == "brand_impersonation_risk"
        )
        assert brand_sig.weight == 0.6


class TestWeakHeaderSignalInVulnerability:
    def test_weak_headers_counted(self):
        from src.fair_signals import compute_fair_signals
        from src.models import DomainResult, SecurityGroup, SecurityHeadersResult, HeaderFinding

        result = DomainResult(
            target="https://example.com",
            security=SecurityGroup(
                headers=SecurityHeadersResult(
                    grade="C", score=55,
                    findings=[
                        HeaderFinding(
                            header="Strict-Transport-Security",
                            status="weak",
                            severity="high",
                            value="max-age=3600",
                            recommendation="HSTS max-age too low.",
                        ),
                        HeaderFinding(
                            header="Content-Security-Policy",
                            status="weak",
                            severity="high",
                            value="default-src * 'unsafe-inline'",
                            recommendation="CSP weak.",
                        ),
                    ],
                ),
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        header_sig = next(
            s for s in signals.vulnerability.signals
            if s.name == "missing_security_headers"
        )
        assert header_sig.score > 0
        assert any("weak" in e for e in header_sig.evidence)
