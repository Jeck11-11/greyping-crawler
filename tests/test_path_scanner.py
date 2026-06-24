"""Tests for the sensitive path scanner."""

from unittest.mock import AsyncMock, patch

import pytest

from src.path_scanner import scan_sensitive_paths


class _FakeResponse:
    def __init__(self, status_code: int = 404, content_length: int = 0, body: bytes = b""):
        self.status_code = status_code
        self.headers = {"content-length": str(content_length)}
        self.content = body
        self.text = body.decode("utf-8", "ignore")


def _is_probe(url: str) -> bool:
    """True for the soft-404 catch-all probe URLs."""
    return "soft404" in url or "should-not-exist" in url


def _install(MockClient, mock_head, mock_get):
    instance = AsyncMock()
    instance.head = mock_head
    instance.get = mock_get
    instance.__aenter__ = AsyncMock(return_value=instance)
    instance.__aexit__ = AsyncMock(return_value=False)
    MockClient.return_value = instance


class TestScanSensitivePaths:
    @pytest.mark.asyncio
    async def test_reports_accessible_env_file(self):
        """/.env returning 200 with real content is reported."""
        original_paths = [
            ("/.env", "Environment file may contain secrets, DB credentials, and API keys.", "critical"),
        ]

        async def mock_head(url, **kwargs):
            if url.endswith("/.env"):
                return _FakeResponse(200, 150)
            return _FakeResponse(404)

        async def mock_get(url, **kwargs):
            if _is_probe(url):
                return _FakeResponse(404)
            if url.endswith("/.env"):
                return _FakeResponse(200, 150, body=b"SECRET_KEY=supersecretvalue1234567890")
            return _FakeResponse(404)

        with patch("src.path_scanner._SENSITIVE_PATHS", original_paths), \
             patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            _install(MockClient, mock_head, mock_get)
            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert len(findings) == 1
        assert findings[0].path == "/.env"
        assert findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_ignores_404_responses(self):
        """All paths returning 404 should produce no findings."""
        async def mock_head(url, **kwargs):
            return _FakeResponse(404)

        async def mock_get(url, **kwargs):
            return _FakeResponse(404)

        with patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            _install(MockClient, mock_head, mock_get)
            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_403_not_reported(self):
        """A 403 no longer counts as the path existing (WAF/CDN default)."""
        original_paths = [
            ("/.env", "Environment file may contain secrets.", "critical"),
        ]

        async def mock_head(url, **kwargs):
            if url.endswith("/.env"):
                return _FakeResponse(403)
            return _FakeResponse(404)

        async def mock_get(url, **kwargs):
            return _FakeResponse(404)

        with patch("src.path_scanner._SENSITIVE_PATHS", original_paths), \
             patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            _install(MockClient, mock_head, mock_get)
            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_empty_200_not_reported(self):
        """A 0-byte 200 (soft-404 / placeholder) is not a real exposed file."""
        original_paths = [
            ("/backup.sql", "SQL dump may contain full database contents.", "critical"),
        ]

        async def mock_head(url, **kwargs):
            if url.endswith("/backup.sql"):
                return _FakeResponse(200, 0)
            return _FakeResponse(404)

        async def mock_get(url, **kwargs):
            if _is_probe(url):
                return _FakeResponse(404)
            if url.endswith("/backup.sql"):
                return _FakeResponse(200, 0, body=b"")  # empty body
            return _FakeResponse(404)

        with patch("src.path_scanner._SENSITIVE_PATHS", original_paths), \
             patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            _install(MockClient, mock_head, mock_get)
            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_catch_all_server_skipped(self):
        """A server returning 200 for nonexistent paths is skipped entirely."""
        original_paths = [
            ("/.env", "Environment file may contain secrets.", "critical"),
            ("/backup.sql", "SQL dump may contain full database contents.", "critical"),
        ]

        async def mock_head(url, **kwargs):
            return _FakeResponse(200, 100)

        async def mock_get(url, **kwargs):
            # Everything (including the soft-404 probes) returns 200.
            return _FakeResponse(200, 100, body=b"x" * 100)

        with patch("src.path_scanner._SENSITIVE_PATHS", original_paths), \
             patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            _install(MockClient, mock_head, mock_get)
            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert findings == []

    @pytest.mark.asyncio
    async def test_ignores_301_redirects(self):
        """301 redirects should NOT be reported as exposed paths."""
        original_paths = [
            ("/.env", "Environment file may contain secrets.", "critical"),
            ("/admin/", "Admin panel path is publicly reachable.", "low"),
        ]

        async def mock_head(url, **kwargs):
            if url.endswith("/.env"):
                return _FakeResponse(301)
            if url.endswith("/admin/"):
                return _FakeResponse(302)
            return _FakeResponse(404)

        async def mock_get(url, **kwargs):
            return _FakeResponse(404)

        with patch("src.path_scanner._SENSITIVE_PATHS", original_paths), \
             patch("src.path_scanner.httpx.AsyncClient") as MockClient:
            _install(MockClient, mock_head, mock_get)
            findings = await scan_sensitive_paths("https://example.com", timeout=5)

        assert len(findings) == 0
