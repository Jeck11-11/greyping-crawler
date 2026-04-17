"""Shared HTTP helpers used by both the orchestrator and the per-capability routers."""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger(__name__)


async def fetch_landing_page(
    target: str,
    *,
    timeout: int = 15,
) -> tuple[dict[str, str], httpx.Cookies]:
    """GET the landing page and return (response_headers, cookies).

    Returns empty results on any failure — the caller decides how to grade
    a target that was unreachable.
    """
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(timeout),
            verify=False,
        ) as client:
            resp = await client.get(
                target,
                headers={"User-Agent": "GreypingCrawler/1.0"},
            )
            return dict(resp.headers), resp.cookies
    except Exception as exc:
        logger.warning("Landing page fetch failed for %s: %s", target, exc)
        return {}, httpx.Cookies()


_STEALTH_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


async def fetch_landing_page_full(
    target: str,
    *,
    timeout: int = 15,
    stealth: bool = False,
) -> tuple[dict[str, str], httpx.Cookies, str]:
    """Like :func:`fetch_landing_page`, but also returns the response body (HTML).

    Used by tech-fingerprinting and JS-intel endpoints that need the HTML.

    When *stealth* is ``True``, swap the honest ``GreypingCrawler/1.0``
    identifier for a realistic Chrome User-Agent plus the modern
    ``Sec-Fetch-*`` headers a real browser sends. This is what the
    light-touch orchestrator uses so a single GET looks like a real
    visitor to a WAF.
    """
    headers = dict(_STEALTH_HEADERS) if stealth else {"User-Agent": "GreypingCrawler/1.0"}
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(timeout),
            verify=False,
        ) as client:
            resp = await client.get(target, headers=headers)
            return dict(resp.headers), resp.cookies, resp.text
    except Exception as exc:
        logger.warning("Landing page fetch (full) failed for %s: %s", target, exc)
        return {}, httpx.Cookies(), ""


def normalise_target(raw: str) -> str:
    """Ensure the target has a scheme so urlparse works correctly."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    return raw
