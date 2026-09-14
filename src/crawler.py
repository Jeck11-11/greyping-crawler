"""Async web crawler with optional headless-browser JS rendering."""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .config import (
    CRAWL_CONCURRENCY,
    CRAWL_TIMEOUT,
    MAX_PAGES,
    MAX_RESPONSE_BYTES,
    PD_TOOLS_API_URL,
    PLAYWRIGHT_EXTRA_WAIT_MS,
    UA_BROWSER,
    UA_HONEST,
)
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
    client: httpx.AsyncClient | None = None,
) -> tuple[str, int | None, list[str]]:
    """Fetch a URL with httpx and return (html, status_code, redirect_chain)."""
    headers = {
        "User-Agent": f"{UA_BROWSER} {UA_HONEST}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }
    async def _request(active_client: httpx.AsyncClient):
        resp = await active_client.get(url, headers=headers)
        chain = [str(r.url) for r in resp.history] if resp.history else []
        body = resp.text[:MAX_RESPONSE_BYTES] if len(resp.content) > MAX_RESPONSE_BYTES else resp.text
        return body, resp.status_code, chain

    if client is not None:
        return await _request(client)

    async with httpx.AsyncClient(
        follow_redirects=follow_redirects,
        timeout=httpx.Timeout(timeout),
        verify=False,  # OSINT scanning may hit self-signed certs
        max_redirects=10,
    ) as owned_client:
        return await _request(owned_client)


async def _fetch_rendered_in_context(
    context: Any,
    url: str,
    *,
    timeout: int,
) -> tuple[str, int | None, list[dict]]:
    """Render one URL in an existing Playwright browser context."""
    page = await context.new_page()
    status_code: int | None = None
    browser_cookies: list[dict] = []
    try:
        response = await page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
        if response:
            status_code = response.status
        await page.wait_for_timeout(PLAYWRIGHT_EXTRA_WAIT_MS)
        html = await page.content()
        browser_cookies = await context.cookies()
        return html, status_code, browser_cookies
    finally:
        await page.close()


async def _fetch_rendered(
    url: str,
    *,
    timeout: int = CRAWL_TIMEOUT,
    context: Any | None = None,
) -> tuple[str, int | None, list[dict]]:
    """Fetch a URL via Playwright headless Chromium to execute JS.

    Returns ``(html, status_code, browser_cookies)`` where
    *browser_cookies* is a list of cookie dicts from the browser context
    (includes JS-set cookies invisible to plain HTTP).
    """
    if context is not None:
        return await _fetch_rendered_in_context(context, url, timeout=timeout)

    from playwright.async_api import async_playwright
    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        owned_context = await browser.new_context(
            user_agent=f"{UA_BROWSER} {UA_HONEST}",
            ignore_https_errors=True,
        )
        try:
            return await _fetch_rendered_in_context(
                owned_context, url, timeout=timeout,
            )
        finally:
            await owned_context.close()
            await browser.close()


async def crawl_page(
    url: str,
    *,
    render_js: bool = True,
    follow_redirects: bool = True,
    timeout: int = CRAWL_TIMEOUT,
    _http_client: httpx.AsyncClient | None = None,
    _browser_context: Any | None = None,
) -> PageResult:
    """Crawl a single page and extract all OSINT data."""
    html: str = ""
    status_code: int | None = None
    redirect_chain: list[str] = []
    notes: str = ""

    try:
        pw_available = await _check_playwright()
        if render_js and pw_available:
            try:
                if _browser_context is None:
                    html, status_code, _browser_cookies = await _fetch_rendered(
                        url, timeout=timeout,
                    )
                else:
                    html, status_code, _browser_cookies = await _fetch_rendered(
                        url, timeout=timeout, context=_browser_context,
                    )
            except Exception as pw_exc:
                logger.warning(
                    "Playwright failed for %s (%s), falling back to static fetch",
                    url, pw_exc,
                )
                html, status_code, redirect_chain = await _fetch_static(
                    url,
                    follow_redirects=follow_redirects,
                    timeout=timeout,
                    client=_http_client,
                )
                notes = f"JS render failed ({pw_exc}), used static fallback"
        else:
            html, status_code, redirect_chain = await _fetch_static(
                url,
                follow_redirects=follow_redirects,
                timeout=timeout,
                client=_http_client,
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
        redirect_chain=redirect_chain,
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


async def fetch_rendered_cookies(
    url: str,
    *,
    timeout: int = CRAWL_TIMEOUT,
) -> list[dict]:
    """Render *url* in a headless browser and return all cookies.

    Returns Playwright cookie dicts (keys: name, value, domain, path,
    httpOnly, secure, sameSite, expires).  Returns empty list if
    Playwright is unavailable or rendering fails.
    """
    if not await _check_playwright():
        return []
    try:
        _html, _status, cookies = await _fetch_rendered(url, timeout=timeout)
        return cookies
    except Exception as exc:
        logger.debug("Rendered cookie fetch failed for %s: %s", url, exc)
        return []


def _katana_to_page_results(katana_result) -> list[PageResult]:
    """Convert katana crawl output to PageResult list using existing extractors."""
    results: list[PageResult] = []
    seen: set[str] = set()
    for endpoint in katana_result.endpoints:
        if not endpoint.url or endpoint.url in seen:
            continue
        seen.add(endpoint.url)
        if not endpoint.body:
            results.append(PageResult(url=endpoint.url, notes="katana: no body"))
            continue
        try:
            soup = BeautifulSoup(endpoint.body, "html.parser")
            title, meta_desc, snippet = extract_page_metadata(soup)
            contacts = extract_contacts(soup, endpoint.body)
            links = extract_links(soup, endpoint.url)
            secrets = scan_secrets(endpoint.body)
            iocs = scan_ioc(endpoint.body, endpoint.url)
            results.append(PageResult(
                url=endpoint.url,
                title=title,
                meta_description=meta_desc,
                content_snippet=snippet,
                contacts=contacts,
                links=links,
                secrets=secrets,
                ioc_findings=iocs,
                notes="katana",
            ))
        except Exception as exc:
            logger.debug("Extraction failed for katana endpoint %s: %s", endpoint.url, exc)
            results.append(PageResult(url=endpoint.url, error=str(exc)))
    return results


async def crawl_domain(
    target: str,
    *,
    render_js: bool = True,
    follow_redirects: bool = True,
    max_depth: int = 2,
    timeout: int = CRAWL_TIMEOUT,
) -> list[PageResult]:
    """Crawl *target* up to *max_depth* levels of internal links.

    Uses katana via the PD tools sidecar when available, otherwise falls
    back to the built-in Python BFS crawler.
    """
    if PD_TOOLS_API_URL:
        try:
            from .katana_client import run_katana_crawl
            katana_result = await run_katana_crawl(
                target, max_depth=max_depth, timeout=timeout,
            )
            if katana_result and not katana_result.error and katana_result.endpoints:
                pages = _katana_to_page_results(katana_result)
                if pages:
                    return pages[:MAX_PAGES]
            logger.info(
                "Katana returned no results for %s, falling back to Python",
                target,
            )
        except Exception as exc:
            logger.warning("Katana crawl failed for %s, falling back to Python: %s", target, exc)

    return await _crawl_domain_python(
        target,
        render_js=render_js,
        follow_redirects=follow_redirects,
        max_depth=max_depth,
        timeout=timeout,
    )


async def _crawl_domain_python(
    target: str,
    *,
    render_js: bool = True,
    follow_redirects: bool = True,
    max_depth: int = 2,
    timeout: int = CRAWL_TIMEOUT,
) -> list[PageResult]:
    """Built-in breadth-first crawler with bounded frontier concurrency.

    A single HTTP client and, when enabled, a single Chromium process/context
    are reused for the target.  The externally-visible list of ``PageResult``
    objects is unchanged.
    """
    async with httpx.AsyncClient(
        follow_redirects=follow_redirects,
        timeout=httpx.Timeout(timeout),
        verify=False,
        max_redirects=10,
    ) as http_client:
        if render_js and await _check_playwright():
            try:
                from playwright.async_api import async_playwright

                async with async_playwright() as pw:
                    browser = await pw.chromium.launch(headless=True)
                    browser_context = await browser.new_context(
                        user_agent=f"{UA_BROWSER} {UA_HONEST}",
                        ignore_https_errors=True,
                    )
                    try:
                        return await _crawl_frontiers(
                            target,
                            render_js=True,
                            follow_redirects=follow_redirects,
                            max_depth=max_depth,
                            timeout=timeout,
                            http_client=http_client,
                            browser_context=browser_context,
                        )
                    finally:
                        await browser_context.close()
                        await browser.close()
            except Exception as exc:
                logger.warning(
                    "Shared Playwright session failed for %s (%s); using static crawl",
                    target,
                    exc,
                )

        return await _crawl_frontiers(
            target,
            render_js=False,
            follow_redirects=follow_redirects,
            max_depth=max_depth,
            timeout=timeout,
            http_client=http_client,
        )


async def _crawl_frontiers(
    target: str,
    *,
    render_js: bool,
    follow_redirects: bool,
    max_depth: int,
    timeout: int,
    http_client: httpx.AsyncClient,
    browser_context: Any | None = None,
) -> list[PageResult]:
    """Crawl breadth-first while fetching each depth frontier concurrently."""
    parsed_target = urlparse(target)
    base_domain = (parsed_target.hostname or "").lower().removeprefix("www.")

    visited: set[str] = set()
    results: list[PageResult] = []
    queue: list[tuple[str, int]] = [(target, 0)]

    max_pages = MAX_PAGES

    while queue and len(results) < max_pages:
        remaining = max_pages - len(results)
        batch: list[tuple[str, int]] = []
        while queue and len(batch) < min(CRAWL_CONCURRENCY, remaining):
            url, depth = queue.pop(0)
            dedup_url = url.split("#", 1)[0]
            if dedup_url in visited or not _is_crawlable_url(dedup_url):
                continue
            visited.add(dedup_url)
            batch.append((dedup_url, depth))

        if not batch:
            continue

        pages = await asyncio.gather(*[
            crawl_page(
                url,
                render_js=render_js,
                follow_redirects=follow_redirects,
                timeout=timeout,
                _http_client=http_client,
                _browser_context=browser_context,
            )
            for url, _depth in batch
        ])
        results.extend(pages)

        for page, (_url, depth) in zip(pages, batch):
            if depth >= max_depth:
                continue
            for link in page.links:
                if link.link_type != "internal":
                    continue
                link_url = link.url.split("#", 1)[0]
                link_host = (urlparse(link_url).hostname or "").lower().removeprefix("www.")
                if link_host == base_domain and link_url not in visited:
                    queue.append((link_url, depth + 1))

    return results
