"""Tests for favicon fetching and hashing."""

import base64
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.favicon import compute_favicon_hash, fetch_favicon, _find_favicon_url


class TestComputeFaviconHash:
    def test_deterministic_hash(self):
        content = b"\x00\x00\x01\x00" + b"\xff" * 100
        h1 = compute_favicon_hash(content)
        h2 = compute_favicon_hash(content)
        assert h1 == h2
        assert isinstance(h1, int)

    def test_different_content_different_hash(self):
        h1 = compute_favicon_hash(b"\x00" * 100)
        h2 = compute_favicon_hash(b"\xff" * 100)
        assert h1 != h2


class TestFindFaviconUrl:
    def test_finds_icon_link(self):
        html = '<html><head><link rel="icon" href="/img/fav.png"></head></html>'
        assert _find_favicon_url(html, "https://example.com") == "https://example.com/img/fav.png"

    def test_finds_shortcut_icon(self):
        html = '<html><head><link rel="shortcut icon" href="/favicon.ico"></head></html>'
        assert _find_favicon_url(html, "https://example.com") == "https://example.com/favicon.ico"

    def test_finds_apple_touch_icon(self):
        html = '<html><head><link rel="apple-touch-icon" href="/touch.png"></head></html>'
        assert _find_favicon_url(html, "https://example.com") == "https://example.com/touch.png"

    def test_resolves_absolute_url(self):
        html = '<html><head><link rel="icon" href="https://cdn.example.com/fav.ico"></head></html>'
        assert _find_favicon_url(html, "https://example.com") == "https://cdn.example.com/fav.ico"

    def test_no_icon_returns_none(self):
        html = "<html><head><title>No icon</title></head></html>"
        assert _find_favicon_url(html, "https://example.com") is None

    def test_empty_html_returns_none(self):
        assert _find_favicon_url("", "https://example.com") is None


class TestFetchFavicon:
    @pytest.mark.asyncio
    async def test_successful_fetch(self):
        favicon_bytes = b"\x00\x00\x01\x00" + b"\x89PNG" + b"\xff" * 100

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = favicon_bytes
        mock_resp.headers = {"content-type": "image/x-icon"}

        with patch("src.favicon.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await fetch_favicon("https://example.com")
            assert result.hash is not None
            assert isinstance(result.hash, int)
            assert result.size_bytes == len(favicon_bytes)
            assert result.error == ""

    @pytest.mark.asyncio
    async def test_no_favicon_returns_error(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b""
        mock_resp.headers = {}

        with patch("src.favicon.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await fetch_favicon("https://example.com", html="")
            assert result.hash is None
            assert "No favicon found" in result.error

    @pytest.mark.asyncio
    async def test_skips_html_error_pages(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html><body>404 Not Found</body></html>" + b" " * 2000
        mock_resp.headers = {"content-type": "text/html"}

        with patch("src.favicon.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await fetch_favicon("https://example.com", html="")
            assert result.hash is None

    @pytest.mark.asyncio
    async def test_tries_linked_favicon_first(self):
        html = '<html><head><link rel="icon" href="/custom-icon.png"></head></html>'
        favicon_bytes = b"\x89PNG" + b"\xff" * 100

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = favicon_bytes
        mock_resp.headers = {"content-type": "image/png"}

        with patch("src.favicon.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await fetch_favicon("https://example.com", html)
            assert result.hash is not None
            call_url = mock_client.get.call_args_list[0][0][0]
            assert "custom-icon.png" in call_url
