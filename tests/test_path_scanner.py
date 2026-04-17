"""Tests for the sensitive path scanner."""

from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.path_scanner import scan_sensitive_paths


class _FakeResponse:
    def __init__(self, status_code: int = 404, content_length: int = 0):
        self.status_code = status_code
        self.headers = {"content-length": str(content_length)}


class TestScanSensitivePaths:
    @pytest.mark.asyncio
    async def test_reports_accessible_env_file(self):
        """Simulate /.env returning 200."""
        original_paths = [
            ("/.env", "Environment file may contain secrets, DB credentials, and API keys.", "critical"),
        ]

        async def mock_client_head(url, **kwargs):
            if "/.env" in url:
                return _FakeResponse(200, 150)
            return _FakeResponse(404)

        with patch("src.path_scanner._SENSITIVE_PATHS", original_paths), \
             patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.head = mock_client_head
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert len(findings) == 1
        assert findings[0].path == "/.env"
        assert findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_ignores_404_responses(self):
        """All paths returning 404 should produce no findings."""
        async def mock_head(url, **kwargs):
            return _FakeResponse(404)

        with patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.head = mock_head
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_403_on_env_reported_as_medium(self):
        """A 403 on a sensitive path still indicates the path exists."""
        original_paths = [
            ("/.env", "Environment file may contain secrets.", "critical"),
        ]

        async def mock_head(url, **kwargs):
            if "/.env" in url:
                return _FakeResponse(403)
            return _FakeResponse(404)

        with patch("src.path_scanner._SENSITIVE_PATHS", original_paths), \
             patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.head = mock_head
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert len(findings) == 1
        assert findings[0].severity == "medium"  # downgraded from critical

    @pytest.mark.asyncio
    async def test_ignores_301_redirects(self):
        """301 redirects should NOT be reported as exposed paths."""
        original_paths = [
            ("/.env", "Environment file may contain secrets.", "critical"),
            ("/admin/", "Admin panel path is publicly reachable.", "low"),
        ]

        async def mock_head(url, **kwargs):
            if "/.env" in url:
                return _FakeResponse(301)
            if "/admin/" in url:
                return _FakeResponse(302)
            return _FakeResponse(404)

        with patch("src.path_scanner._SENSITIVE_PATHS", original_paths), \
             patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            instance = AsyncMock()
            instance.head = mock_head
            instance.__aenter__ = AsyncMock(return_value=instance)
            instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = instance

            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert len(findings) == 0
