"""Tests for the ProjectDiscovery httpx probe client."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.httpx_client import _parse_httpx_jsonl, run_httpx_probe
from src.models import HttpxProbeResult


class TestHttpxParsing:
    def test_parse_jsonl_standard(self):
        text = '{"url":"https://example.com","status_code":200,"title":"Example","tech":["Nginx","jQuery"],"webserver":"nginx/1.18"}\n'
        results = _parse_httpx_jsonl(text)
        assert len(results) == 1
        assert results[0].url == "https://example.com"
        assert results[0].status_code == 200
        assert results[0].title == "Example"
        assert "Nginx" in results[0].technologies
        assert "jQuery" in results[0].technologies
        assert results[0].webserver == "nginx/1.18"

    def test_parse_jsonl_hyphenated_keys(self):
        text = '{"url":"https://x.com","status-code":301,"content-type":"text/html","response-time":"123ms"}\n'
        results = _parse_httpx_jsonl(text)
        assert len(results) == 1
        assert results[0].status_code == 301
        assert results[0].content_type == "text/html"
        assert results[0].response_time == "123ms"

    def test_parse_jsonl_skips_bad_lines(self):
        text = 'not json\n\n{"url":"https://good.com","status_code":200}\n'
        results = _parse_httpx_jsonl(text)
        assert len(results) == 1
        assert results[0].url == "https://good.com"

    def test_parse_empty(self):
        assert _parse_httpx_jsonl("") == []
        assert _parse_httpx_jsonl("\n\n") == []


class TestRunHttpxProbe:
    @patch("src.httpx_client.PD_TOOLS_API_URL", "")
    @pytest.mark.asyncio
    async def test_returns_empty_when_no_url(self):
        result = await run_httpx_probe(["https://example.com"])
        assert result == []

    @patch("src.httpx_client.PD_TOOLS_API_URL", "http://pd-tools:8080")
    @patch("src.httpx_client.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_parses_structured_response(self, mock_client_cls):
        from unittest.mock import MagicMock

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "results": [
                {
                    "url": "https://example.com",
                    "status_code": 200,
                    "title": "Example",
                    "technologies": ["Cloudflare", "React"],
                    "webserver": "cloudflare",
                }
            ],
            "count": 1,
        }
        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        results = await run_httpx_probe(["https://example.com"])
        assert len(results) == 1
        assert results[0].url == "https://example.com"
        assert "Cloudflare" in results[0].technologies
        assert "React" in results[0].technologies

    @patch("src.httpx_client.PD_TOOLS_API_URL", "http://pd-tools:8080")
    @patch("src.httpx_client.httpx.AsyncClient")
    @pytest.mark.asyncio
    async def test_returns_empty_on_failure(self, mock_client_cls):
        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("connection refused")
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client_cls.return_value = mock_client

        results = await run_httpx_probe(["https://example.com"])
        assert results == []
