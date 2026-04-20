"""Tests for crawler module — redirect chain and response size limits."""

import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

from src.crawler import _fetch_static, crawl_page


class TestFetchStaticRedirectChain:
    @pytest.mark.asyncio
    async def test_no_redirects_returns_empty_chain(self):
        mock_resp = MagicMock()
        mock_resp.text = "<html>hello</html>"
        mock_resp.content = b"<html>hello</html>"
        mock_resp.status_code = 200
        mock_resp.history = []

        with patch("src.crawler.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            html, status, chain = await _fetch_static("https://example.com")
            assert chain == []
            assert status == 200

    @pytest.mark.asyncio
    async def test_redirects_captured_in_chain(self):
        redirect_1 = MagicMock()
        redirect_1.url = httpx.URL("http://example.com")
        redirect_2 = MagicMock()
        redirect_2.url = httpx.URL("https://example.com")

        mock_resp = MagicMock()
        mock_resp.text = "<html>final</html>"
        mock_resp.content = b"<html>final</html>"
        mock_resp.status_code = 200
        mock_resp.history = [redirect_1, redirect_2]

        with patch("src.crawler.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            html, status, chain = await _fetch_static("http://example.com")
            assert len(chain) == 2
            assert "http://example.com" in chain[0]
            assert "https://example.com" in chain[1]


class TestResponseSizeLimit:
    @pytest.mark.asyncio
    async def test_oversized_response_truncated(self):
        big_body = "x" * (11 * 1024 * 1024)
        mock_resp = MagicMock()
        mock_resp.text = big_body
        mock_resp.content = big_body.encode()
        mock_resp.status_code = 200
        mock_resp.history = []

        with patch("src.crawler.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            html, status, chain = await _fetch_static("https://example.com")
            assert len(html) <= 10 * 1024 * 1024

    @pytest.mark.asyncio
    async def test_normal_response_not_truncated(self):
        body = "<html>small page</html>"
        mock_resp = MagicMock()
        mock_resp.text = body
        mock_resp.content = body.encode()
        mock_resp.status_code = 200
        mock_resp.history = []

        with patch("src.crawler.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            html, status, chain = await _fetch_static("https://example.com")
            assert html == body


class TestCrawlPageRedirectChain:
    @pytest.mark.asyncio
    async def test_redirect_chain_in_page_result(self):
        redirect_1 = MagicMock()
        redirect_1.url = httpx.URL("http://example.com")

        mock_resp = MagicMock()
        mock_resp.text = "<html><head><title>Test</title></head><body>hello</body></html>"
        mock_resp.content = mock_resp.text.encode()
        mock_resp.status_code = 200
        mock_resp.history = [redirect_1]

        with patch("src.crawler.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with patch("src.crawler._check_playwright", return_value=False):
                page = await crawl_page("http://example.com", render_js=False)
                assert len(page.redirect_chain) == 1
                assert "http://example.com" in page.redirect_chain[0]
