"""Tests for c99_client module."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.c99_client import (
    find_subdomains,
    check_ip_reputation,
    check_url_reputation,
    validate_email,
)


def _mock_response(json_data, status_code=200):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status_code
    resp.raise_for_status = MagicMock()
    return resp


@pytest.fixture
def mock_c99_key():
    with patch("src.c99_client.C99_API_KEY", "test-key"):
        yield


# ---------------------------------------------------------------------------
# find_subdomains
# ---------------------------------------------------------------------------

class TestFindSubdomains:
    @pytest.mark.asyncio
    async def test_returns_subdomains(self, mock_c99_key):
        api_response = {
            "success": True,
            "subdomains": [
                {"subdomain": "api.example.com"},
                {"subdomain": "mail.example.com"},
            ],
        }
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response(api_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await find_subdomains("example.com")
            assert "api.example.com" in result
            assert "mail.example.com" in result

    @pytest.mark.asyncio
    async def test_returns_empty_on_failure(self, mock_c99_key):
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response({"success": False})
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await find_subdomains("example.com")
            assert result == []

    @pytest.mark.asyncio
    async def test_returns_empty_without_api_key(self):
        with patch("src.c99_client.C99_API_KEY", ""):
            result = await find_subdomains("example.com")
            assert result == []

    @pytest.mark.asyncio
    async def test_handles_string_entries(self, mock_c99_key):
        api_response = {
            "success": True,
            "subdomains": ["api.example.com", "cdn.example.com"],
        }
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response(api_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await find_subdomains("example.com")
            assert len(result) == 2


# ---------------------------------------------------------------------------
# check_ip_reputation
# ---------------------------------------------------------------------------

class TestCheckIPReputation:
    @pytest.mark.asyncio
    async def test_clean_ip(self, mock_c99_key):
        api_response = {
            "success": True,
            "result": {"malicious": False, "details": {}},
        }
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response(api_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await check_ip_reputation("1.1.1.1")
            assert result["ip"] == "1.1.1.1"
            assert result["malicious"] is False

    @pytest.mark.asyncio
    async def test_malicious_ip(self, mock_c99_key):
        api_response = {
            "success": True,
            "result": {"malicious": True, "details": {"spam": True}},
        }
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response(api_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await check_ip_reputation("134.209.199.4")
            assert result["malicious"] is True

    @pytest.mark.asyncio
    async def test_no_api_key(self):
        with patch("src.c99_client.C99_API_KEY", ""):
            result = await check_ip_reputation("1.1.1.1")
            assert result["malicious"] is False
            assert "error" in result


# ---------------------------------------------------------------------------
# check_url_reputation
# ---------------------------------------------------------------------------

class TestCheckURLReputation:
    @pytest.mark.asyncio
    async def test_clean_url(self, mock_c99_key):
        api_response = {
            "success": True,
            "result": {"google_safebrowsing": "clean", "phishtank": "clean"},
        }
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response(api_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await check_url_reputation("https://example.com")
            assert result["blacklisted"] is False
            assert result["sources_checked"] == 2

    @pytest.mark.asyncio
    async def test_blacklisted_url(self, mock_c99_key):
        api_response = {
            "success": True,
            "result": {"google_safebrowsing": "blacklisted", "phishtank": "clean"},
        }
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response(api_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await check_url_reputation("https://malicious.com")
            assert result["blacklisted"] is True
            assert len(result["detections"]) == 1


# ---------------------------------------------------------------------------
# validate_email
# ---------------------------------------------------------------------------

class TestValidateEmail:
    @pytest.mark.asyncio
    async def test_valid_email(self, mock_c99_key):
        api_response = {
            "success": True,
            "result": {
                "valid": True,
                "disposable": False,
                "role": False,
                "free": True,
            },
        }
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response(api_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await validate_email("user@example.com")
            assert result["email"] == "user@example.com"
            assert result["valid"] is True
            assert result["free_provider"] is True

    @pytest.mark.asyncio
    async def test_invalid_email(self, mock_c99_key):
        api_response = {
            "success": True,
            "result": {"valid": False, "disposable": False},
        }
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response(api_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await validate_email("fake@nowhere.xyz")
            assert result["valid"] is False

    @pytest.mark.asyncio
    async def test_disposable_email(self, mock_c99_key):
        api_response = {
            "success": True,
            "result": {"valid": True, "disposable": True, "role": False, "free": True},
        }
        with patch("src.c99_client.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = _mock_response(api_response)
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await validate_email("temp@yopmail.com")
            assert result["disposable"] is True


# ---------------------------------------------------------------------------
# FAIR signal integration
# ---------------------------------------------------------------------------

class TestFAIRReputation:
    def test_malicious_ip_signal(self):
        from src.models import DomainResult, DomainSummary, IPReputationResult
        from src.fair_signals import compute_fair_signals

        result = DomainResult(
            target="https://example.com",
            summary=DomainSummary(),
            ip_reputation=IPReputationResult(
                ip="1.2.3.4", malicious=True, detections=["spam list"],
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        names = [s.name for s in signals.vulnerability.signals]
        assert "ip_reputation_malicious" in names

    def test_clean_ip_no_signal(self):
        from src.models import DomainResult, DomainSummary, IPReputationResult
        from src.fair_signals import compute_fair_signals

        result = DomainResult(
            target="https://example.com",
            summary=DomainSummary(),
            ip_reputation=IPReputationResult(ip="1.2.3.4", malicious=False),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        names = [s.name for s in signals.vulnerability.signals]
        assert "ip_reputation_malicious" not in names

    def test_blacklisted_url_signal(self):
        from src.models import DomainResult, DomainSummary, URLReputationResult
        from src.fair_signals import compute_fair_signals

        result = DomainResult(
            target="https://example.com",
            summary=DomainSummary(),
            url_reputation=URLReputationResult(
                url="https://example.com",
                blacklisted=True,
                detections=["google_safebrowsing: blacklisted"],
                sources_checked=5,
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        names = [s.name for s in signals.vulnerability.signals]
        assert "url_blacklisted" in names

    def test_clean_url_no_signal(self):
        from src.models import DomainResult, DomainSummary, URLReputationResult
        from src.fair_signals import compute_fair_signals

        result = DomainResult(
            target="https://example.com",
            summary=DomainSummary(),
            url_reputation=URLReputationResult(
                url="https://example.com", blacklisted=False, sources_checked=5,
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        names = [s.name for s in signals.vulnerability.signals]
        assert "url_blacklisted" not in names
