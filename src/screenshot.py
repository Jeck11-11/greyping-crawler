"""Screenshot capture via Playwright headless Chromium."""

from __future__ import annotations

import base64
import logging

from .config import SCREENSHOT_HEIGHT, SCREENSHOT_TIMEOUT, SCREENSHOT_WIDTH
from .models import ScreenshotResult

logger = logging.getLogger(__name__)

_PLAYWRIGHT_AVAILABLE: bool | None = None


async def _check_playwright() -> bool:
    global _PLAYWRIGHT_AVAILABLE
    if _PLAYWRIGHT_AVAILABLE is not None:
        return _PLAYWRIGHT_AVAILABLE
    try:
        from playwright.async_api import async_playwright  # noqa: F401
        _PLAYWRIGHT_AVAILABLE = True
    except ImportError:
        _PLAYWRIGHT_AVAILABLE = False
        logger.warning("playwright not installed — screenshots disabled")
    return _PLAYWRIGHT_AVAILABLE


async def take_screenshot(
    url: str,
    *,
    width: int = SCREENSHOT_WIDTH,
    height: int = SCREENSHOT_HEIGHT,
    timeout_ms: int = SCREENSHOT_TIMEOUT,
) -> ScreenshotResult:
    if not await _check_playwright():
        return ScreenshotResult(url=url, error="Playwright not available")

    from playwright.async_api import async_playwright

    try:
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            page = await browser.new_page(viewport={"width": width, "height": height})
            try:
                await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception:
                await page.goto(url, wait_until="load", timeout=timeout_ms)
            png_bytes = await page.screenshot(type="png", full_page=False)
            await browser.close()

        encoded = base64.b64encode(png_bytes).decode("ascii")
        return ScreenshotResult(
            url=url,
            image_base64=encoded,
            width=width,
            height=height,
            size_bytes=len(png_bytes),
        )
    except Exception as exc:
        logger.warning("Screenshot failed for %s: %s", url, exc)
        return ScreenshotResult(url=url, error=str(exc))


__all__ = ["take_screenshot"]
