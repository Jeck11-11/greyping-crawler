"""Tests for the katana web crawler client and crawler augmentation."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.crawler import _katana_to_page_results, crawl_domain
from src.models import KatanaCrawlResult, KatanaEndpoint, PageResult


class TestKatanaToPageResults:
    def test_converts_endpoints_with_bodies(self):
        katana = KatanaCrawlResult(
            target="https://example.com",
            endpoints=[
                KatanaEndpoint(
                    url="https://example.com",
                    body="<html><head><title>Example</title></head><body>test@example.com</body></html>",
                ),
                KatanaEndpoint(
                    url="https://example.com/about",
                    body="<html><head><title>About</title></head><body>Hello</body></html>",
                ),
            ],
        )
        results = _katana_to_page_results(katana)
        assert len(results) == 2
        assert results[0].url == "https://example.com"
        assert results[0].title == "Example"
        assert results[1].url == "https://example.com/about"
        assert results[1].title == "About"

    def test_extracts_contacts(self):
        katana = KatanaCrawlResult(
            target="https://example.com",
            endpoints=[
                KatanaEndpoint(
                    url="https://example.com",
                    body="<html><body>Contact us: admin@example.com, sales@example.com</body></html>",
                ),
            ],
        )
        results = _katana_to_page_results(katana)
        assert len(results) == 1
        assert results[0].contacts.emails

    def test_handles_empty_body(self):
        katana = KatanaCrawlResult(
            target="https://example.com",
            endpoints=[
                KatanaEndpoint(url="https://example.com/page", body=""),
            ],
        )
        results = _katana_to_page_results(katana)
        assert len(results) == 1
        assert results[0].notes == "katana: no body"

    def test_deduplicates_urls(self):
        katana = KatanaCrawlResult(
            target="https://example.com",
            endpoints=[
                KatanaEndpoint(url="https://example.com", body="<html>A</html>"),
                KatanaEndpoint(url="https://example.com", body="<html>B</html>"),
            ],
        )
        results = _katana_to_page_results(katana)
        assert len(results) == 1

    def test_empty_endpoints(self):
        katana = KatanaCrawlResult(target="https://example.com", endpoints=[])
        results = _katana_to_page_results(katana)
        assert results == []


class TestKatanaClientParsing:
    def test_parse_jsonl(self):
        from src.katana_client import _parse_katana_jsonl

        text = '{"request":{"endpoint":"https://example.com","method":"GET"},"response":{"body":"<html>hi</html>"}}\n'
        endpoints = _parse_katana_jsonl(text)
        assert len(endpoints) == 1
        assert endpoints[0].url == "https://example.com"
        assert endpoints[0].body == "<html>hi</html>"

    def test_parse_jsonl_flat_format(self):
        from src.katana_client import _parse_katana_jsonl

        text = '{"endpoint":"https://example.com/about","source":"https://example.com","tag":"a"}\n'
        endpoints = _parse_katana_jsonl(text)
        assert len(endpoints) == 1
        assert endpoints[0].url == "https://example.com/about"

    def test_parse_jsonl_skips_bad(self):
        from src.katana_client import _parse_katana_jsonl

        text = 'garbage\n{}\n{"endpoint":"https://x.com"}\n'
        endpoints = _parse_katana_jsonl(text)
        assert len(endpoints) == 1


class TestCrawlDomainFallback:
    @patch("src.crawler.PD_TOOLS_API_URL", "")
    @pytest.mark.asyncio
    async def test_uses_python_when_no_pd_url(self):
        with patch("src.crawler._crawl_domain_python", new_callable=AsyncMock) as mock_python:
            mock_python.return_value = [PageResult(url="https://example.com")]
            result = await crawl_domain("https://example.com")
            mock_python.assert_called_once()

    @patch("src.crawler.PD_TOOLS_API_URL", "http://pd-tools:8080")
    @pytest.mark.asyncio
    async def test_uses_katana_when_pd_url_set(self):
        katana_result = KatanaCrawlResult(
            target="https://example.com",
            endpoints=[
                KatanaEndpoint(
                    url="https://example.com",
                    body="<html><head><title>Test</title></head><body>hi</body></html>",
                ),
            ],
        )
        with patch("src.katana_client.run_katana_crawl", new_callable=AsyncMock, return_value=katana_result):
            result = await crawl_domain("https://example.com")
            assert len(result) == 1
            assert result[0].title == "Test"

    @patch("src.crawler.PD_TOOLS_API_URL", "http://pd-tools:8080")
    @pytest.mark.asyncio
    async def test_falls_back_on_katana_error(self):
        katana_result = KatanaCrawlResult(target="https://example.com", error="timeout")
        with patch("src.katana_client.run_katana_crawl", new_callable=AsyncMock, return_value=katana_result):
            with patch("src.crawler._crawl_domain_python", new_callable=AsyncMock) as mock_python:
                mock_python.return_value = [PageResult(url="https://example.com")]
                result = await crawl_domain("https://example.com")
                mock_python.assert_called_once()

    @patch("src.crawler.PD_TOOLS_API_URL", "http://pd-tools:8080")
    @pytest.mark.asyncio
    async def test_falls_back_on_katana_exception(self):
        with patch("src.katana_client.run_katana_crawl", new_callable=AsyncMock, side_effect=RuntimeError("boom")):
            with patch("src.crawler._crawl_domain_python", new_callable=AsyncMock) as mock_python:
                mock_python.return_value = [PageResult(url="https://example.com")]
                result = await crawl_domain("https://example.com")
                mock_python.assert_called_once()
