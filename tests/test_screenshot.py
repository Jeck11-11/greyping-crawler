"""Tests for the screenshot capture module."""

from __future__ import annotations

import base64
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.screenshot import take_screenshot, _check_playwright
from src.models import ScreenshotResult


# ---------------------------------------------------------------------------
# Playwright unavailable
# ---------------------------------------------------------------------------


class TestScreenshotPlaywrightUnavailable:
    """When Playwright is not installed, take_screenshot returns an error."""

    @pytest.mark.asyncio
    async def test_returns_error_when_playwright_missing(self):
        import src.screenshot as mod
        original = mod._PLAYWRIGHT_AVAILABLE
        try:
            mod._PLAYWRIGHT_AVAILABLE = False
            result = await take_screenshot("https://example.com")
            assert isinstance(result, ScreenshotResult)
            assert result.url == "https://example.com"
            assert result.error == "Playwright not available"
            assert result.image_base64 == ""
        finally:
            mod._PLAYWRIGHT_AVAILABLE = original


# ---------------------------------------------------------------------------
# Playwright available (mocked)
# ---------------------------------------------------------------------------


def _make_mock_playwright(png_data: bytes = b"\x89PNG_FAKE"):
    """Build a mock async Playwright context manager chain."""
    mock_page = AsyncMock()
    mock_page.goto = AsyncMock()
    mock_page.screenshot = AsyncMock(return_value=png_data)

    mock_browser = AsyncMock()
    mock_browser.new_page = AsyncMock(return_value=mock_page)
    mock_browser.close = AsyncMock()

    mock_chromium = AsyncMock()
    mock_chromium.launch = AsyncMock(return_value=mock_browser)

    mock_pw_instance = MagicMock()
    mock_pw_instance.chromium = mock_chromium

    mock_pw_cm = AsyncMock()
    mock_pw_cm.__aenter__ = AsyncMock(return_value=mock_pw_instance)
    mock_pw_cm.__aexit__ = AsyncMock(return_value=False)

    return mock_pw_cm, mock_page, mock_browser


class TestScreenshotCapture:
    """Tests with mocked Playwright — verify the happy path."""

    @pytest.mark.asyncio
    async def test_successful_screenshot(self):
        import src.screenshot as mod
        original = mod._PLAYWRIGHT_AVAILABLE
        try:
            mod._PLAYWRIGHT_AVAILABLE = True
            png = b"\x89PNG_TEST_DATA_1234567890"
            mock_pw, mock_page, mock_browser = _make_mock_playwright(png)

            mock_api_module = MagicMock()
            mock_api_module.async_playwright = MagicMock(return_value=mock_pw)
            with patch.dict("sys.modules", {"playwright.async_api": mock_api_module}):
                result = await take_screenshot("https://example.com")

            assert result.url == "https://example.com"
            assert result.error is None
            assert result.image_base64 == base64.b64encode(png).decode("ascii")
            assert result.width == 1280
            assert result.height == 720
            assert result.size_bytes == len(png)
        finally:
            mod._PLAYWRIGHT_AVAILABLE = original

    @pytest.mark.asyncio
    async def test_custom_dimensions(self):
        import src.screenshot as mod
        original = mod._PLAYWRIGHT_AVAILABLE
        try:
            mod._PLAYWRIGHT_AVAILABLE = True
            mock_pw, mock_page, mock_browser = _make_mock_playwright()

            mock_api_module = MagicMock()
            mock_api_module.async_playwright = MagicMock(return_value=mock_pw)
            with patch.dict("sys.modules", {"playwright.async_api": mock_api_module}):
                result = await take_screenshot(
                    "https://example.com", width=800, height=600,
                )

            assert result.width == 800
            assert result.height == 600
            mock_browser.new_page.assert_called_once_with(
                viewport={"width": 800, "height": 600},
            )
        finally:
            mod._PLAYWRIGHT_AVAILABLE = original

    @pytest.mark.asyncio
    async def test_browser_error_returns_error_result(self):
        import src.screenshot as mod
        original = mod._PLAYWRIGHT_AVAILABLE
        try:
            mod._PLAYWRIGHT_AVAILABLE = True
            mock_pw_cm = AsyncMock()
            mock_pw_instance = MagicMock()
            mock_pw_instance.chromium.launch = AsyncMock(
                side_effect=RuntimeError("Browser crash"),
            )
            mock_pw_cm.__aenter__ = AsyncMock(return_value=mock_pw_instance)
            mock_pw_cm.__aexit__ = AsyncMock(return_value=False)

            mock_api_module = MagicMock()
            mock_api_module.async_playwright = MagicMock(return_value=mock_pw_cm)
            with patch.dict("sys.modules", {"playwright.async_api": mock_api_module}):
                result = await take_screenshot("https://example.com")

            assert result.url == "https://example.com"
            assert "Browser crash" in result.error
            assert result.image_base64 == ""
        finally:
            mod._PLAYWRIGHT_AVAILABLE = original


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestScreenshotResultModel:
    def test_default_values(self):
        r = ScreenshotResult(url="https://example.com")
        assert r.url == "https://example.com"
        assert r.image_base64 == ""
        assert r.width == 0
        assert r.height == 0
        assert r.size_bytes == 0
        assert r.error is None

    def test_with_data(self):
        r = ScreenshotResult(
            url="https://example.com/admin",
            image_base64="abc123",
            width=1280,
            height=720,
            size_bytes=50000,
        )
        assert r.width == 1280
        assert r.size_bytes == 50000

    def test_error_result(self):
        r = ScreenshotResult(url="https://example.com", error="timeout")
        assert r.error == "timeout"
        assert r.image_base64 == ""


# ---------------------------------------------------------------------------
# Check playwright function
# ---------------------------------------------------------------------------


class TestCheckPlaywright:
    @pytest.mark.asyncio
    async def test_caches_result(self):
        import src.screenshot as mod
        original = mod._PLAYWRIGHT_AVAILABLE
        try:
            mod._PLAYWRIGHT_AVAILABLE = None
            with patch.dict("sys.modules", {"playwright": None, "playwright.async_api": None}):
                mod._PLAYWRIGHT_AVAILABLE = None
                result = await _check_playwright()
                assert isinstance(result, bool)
                second = await _check_playwright()
                assert result == second
        finally:
            mod._PLAYWRIGHT_AVAILABLE = original
