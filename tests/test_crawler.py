"""Tests for crawler module — redirect chain and response size limits."""

import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import httpx
import pytest

from src.crawler import _crawl_domain_python, _fetch_static, crawl_page
from src.models import LinkInfo, PageResult


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
    async def test_reuses_supplied_http_client(self):
        mock_resp = MagicMock()
        mock_resp.text = "<html>shared</html>"
        mock_resp.content = b"<html>shared</html>"
        mock_resp.status_code = 200
        mock_resp.history = []
        shared_client = AsyncMock()
        shared_client.get.return_value = mock_resp

        with patch("src.crawler.httpx.AsyncClient") as mock_client_cls:
            html, status, chain = await _fetch_static(
                "https://example.com", client=shared_client,
            )

        mock_client_cls.assert_not_called()
        shared_client.get.assert_awaited_once()
        assert (html, status, chain) == ("<html>shared</html>", 200, [])

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


class TestPlaywrightFallback:
    @pytest.mark.asyncio
    async def test_falls_back_to_static_when_playwright_fails(self):
        mock_resp = MagicMock()
        mock_resp.text = (
            '<html><head><title>Fallback</title></head>'
            '<body>Contact: info@acme.com</body></html>'
        )
        mock_resp.content = mock_resp.text.encode()
        mock_resp.status_code = 200
        mock_resp.history = []

        with patch("src.crawler.httpx.AsyncClient") as mock_client_cls:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            with patch("src.crawler._check_playwright", return_value=True):
                with patch(
                    "src.crawler._fetch_rendered",
                    side_effect=RuntimeError("TLS connection failed: timed out"),
                ):
                    page = await crawl_page(
                        "https://example.com", render_js=True,
                    )
                    assert page.error is None
                    assert page.title == "Fallback"
                    assert "info@acme.com" in page.contacts.emails
                    assert "static fallback" in page.notes


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


class TestConcurrentDomainCrawl:
    @pytest.mark.asyncio
    async def test_fetches_frontier_with_bounded_concurrency_and_dedupes_fragments(self):
        active = 0
        peak = 0

        async def fake_crawl_page(url: str, **_kwargs) -> PageResult:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            links = []
            if url == "https://example.com":
                links = [
                    LinkInfo(url="https://example.com/a#one", link_type="internal"),
                    LinkInfo(url="https://example.com/a#two", link_type="internal"),
                    LinkInfo(url="https://example.com/b", link_type="internal"),
                    LinkInfo(url="https://example.com/c", link_type="internal"),
                ]
            return PageResult(url=url, status_code=200, links=links)

        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("src.crawler._check_playwright", new_callable=AsyncMock, return_value=False), \
             patch("src.crawler.CRAWL_CONCURRENCY", 2), \
             patch("src.crawler.httpx.AsyncClient", return_value=mock_client), \
             patch("src.crawler.crawl_page", side_effect=fake_crawl_page):
            pages = await _crawl_domain_python(
                "https://example.com", render_js=False, max_depth=1,
            )

        assert peak == 2
        assert [page.url for page in pages] == [
            "https://example.com",
            "https://example.com/a",
            "https://example.com/b",
            "https://example.com/c",
        ]

    @pytest.mark.asyncio
    async def test_reuses_one_browser_context_for_rendered_pages(self):
        context = AsyncMock()
        browser = AsyncMock()
        browser.new_context.return_value = context
        playwright = MagicMock()
        playwright.chromium.launch = AsyncMock(return_value=browser)
        playwright_manager = AsyncMock()
        playwright_manager.__aenter__ = AsyncMock(return_value=playwright)
        playwright_manager.__aexit__ = AsyncMock(return_value=False)

        http_client = AsyncMock()
        http_client.__aenter__ = AsyncMock(return_value=http_client)
        http_client.__aexit__ = AsyncMock(return_value=False)
        seen_contexts = []

        async def fake_crawl_page(url: str, **kwargs) -> PageResult:
            seen_contexts.append(kwargs.get("_browser_context"))
            links = (
                [LinkInfo(url="https://example.com/about", link_type="internal")]
                if url == "https://example.com" else []
            )
            return PageResult(url=url, status_code=200, links=links)

        with patch("src.crawler._check_playwright", new_callable=AsyncMock, return_value=True), \
             patch("src.crawler.httpx.AsyncClient", return_value=http_client), \
             patch("playwright.async_api.async_playwright", return_value=playwright_manager), \
             patch("src.crawler.crawl_page", side_effect=fake_crawl_page):
            pages = await _crawl_domain_python(
                "https://example.com", render_js=True, max_depth=1,
            )

        assert len(pages) == 2
        playwright.chromium.launch.assert_awaited_once()
        browser.new_context.assert_awaited_once()
        assert seen_contexts == [context, context]
