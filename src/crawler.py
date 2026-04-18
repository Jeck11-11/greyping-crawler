"""Async web crawler with optional headless-browser JS rendering."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .config import CRAWL_TIMEOUT, MAX_PAGES, PLAYWRIGHT_EXTRA_WAIT_MS, UA_BROWSER, UA_HONEST
from .extractors import extract_contacts, extract_links, extract_page_metadata
from .ioc_scanner import scan_ioc
from .models import ContactInfo, LinkInfo, PageResult
from .secret_scanner import scan_secrets

logger = logging.getLogger(__name__)

# Playwright is optional – imported lazily so the module still works
# in lightweight environments that only need static crawling.
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
        logger.warning("playwright not installed – JS rendering disabled")
    return _PLAYWRIGHT_AVAILABLE


async def _fetch_static(
    url: str,
    *,
    follow_redirects: bool = True,
    timeout: int = CRAWL_TIMEOUT,
) -> tuple[str, int | None]:
    """Fetch a URL with httpx and return (html, status_code)."""
    headers = {
        "User-Agent": f"{UA_BROWSER} {UA_HONEST}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    async with httpx.AsyncClient(
        follow_redirects=follow_redirects,
        timeout=httpx.Timeout(timeout),
        verify=False,  # OSINT scanning may hit self-signed certs
    ) as client:
        resp = await client.get(url, headers=headers)
        return resp.text, resp.status_code


async def _fetch_rendered(
    url: str,
    *,
    timeout: int = CRAWL_TIMEOUT,
) -> tuple[str, int | None]:
    """Fetch a URL via Playwright headless Chromium to execute JS."""
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        context = await browser.new_context(
            user_agent=f"{UA_BROWSER} {UA_HONEST}",
            ignore_https_errors=True,
        )
        page = await context.new_page()
        status_code: int | None = None
        try:
            response = await page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
            if response:
                status_code = response.status
            # Give extra time for late-loading XHR / SPA hydration
            await page.wait_for_timeout(PLAYWRIGHT_EXTRA_WAIT_MS)
            html = await page.content()
        finally:
            await context.close()
            await browser.close()
    return html, status_code


async def crawl_page(
    url: str,
    *,
    render_js: bool = True,
    follow_redirects: bool = True,
    timeout: int = CRAWL_TIMEOUT,
) -> PageResult:
    """Crawl a single page and extract all OSINT data."""
    html: str = ""
    status_code: int | None = None
    notes: str = ""

    try:
        pw_available = await _check_playwright()
        if render_js and pw_available:
            html, status_code = await _fetch_rendered(url, timeout=timeout)
        else:
            if render_js and not pw_available:
                notes = "Playwright unavailable; fell back to static fetch"
            html, status_code = await _fetch_static(
                url, follow_redirects=follow_redirects, timeout=timeout,
            )
    except Exception as exc:
        return PageResult(url=url, error=str(exc))

    soup = BeautifulSoup(html, "html.parser")
    title, meta_desc, snippet = extract_page_metadata(soup)
    contacts = extract_contacts(soup, html)
    links = extract_links(soup, url)
    secrets = scan_secrets(html)
    iocs = scan_ioc(html, url)

    return PageResult(
        url=url,
        status_code=status_code,
        title=title,
        meta_description=meta_desc,
        content_snippet=snippet,
        links=links,
        contacts=contacts,
        secrets=secrets,
        ioc_findings=iocs,
        notes=notes,
    )


_SKIP_EXTENSIONS = frozenset({
    ".pdf", ".pptx", ".ppt", ".docx", ".doc", ".xlsx", ".xls",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv", ".wav", ".ogg",
    ".woff", ".woff2", ".ttf", ".eot",
    ".exe", ".msi", ".dmg", ".iso", ".apk",
})


def _is_crawlable_url(url: str) -> bool:
    """Return False for URLs pointing to binary/non-HTML files."""
    path = urlparse(url).path.lower()
    return not any(path.endswith(ext) for ext in _SKIP_EXTENSIONS)


async def crawl_domain(
    target: str,
    *,
    render_js: bool = True,
    follow_redirects: bool = True,
    max_depth: int = 2,
    timeout: int = CRAWL_TIMEOUT,
) -> list[PageResult]:
    """Crawl *target* up to *max_depth* levels of internal links.

    Returns a list of :class:`PageResult` – one per crawled page.
    """
    parsed_target = urlparse(target)
    base_domain = (parsed_target.hostname or "").lower().lstrip("www.")

    visited: set[str] = set()
    results: list[PageResult] = []
    queue: list[tuple[str, int]] = [(target, 0)]

    # Cap total pages to prevent runaway scans
    max_pages = MAX_PAGES

    while queue and len(results) < max_pages:
        url, depth = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)

        if not _is_crawlable_url(url):
            continue

        page = await crawl_page(
            url,
            render_js=render_js,
            follow_redirects=follow_redirects,
            timeout=timeout,
        )
        results.append(page)

        # Enqueue internal links for deeper crawling
        if depth < max_depth:
            for link in page.links:
                if link.link_type == "internal" and link.url not in visited:
                    queue.append((link.url, depth + 1))

    return results
