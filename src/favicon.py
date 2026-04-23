"""Favicon fetching and MurmurHash3 hashing for Shodan/Censys pivoting."""

from __future__ import annotations

import base64
import logging
from urllib.parse import urljoin

import httpx
import mmh3
from bs4 import BeautifulSoup

from .config import HTTP_TIMEOUT, UA_HONEST
from .models import FaviconResult

logger = logging.getLogger(__name__)

_FAVICON_PATHS = ["/favicon.ico", "/apple-touch-icon.png"]


def _find_favicon_url(html: str, base_url: str) -> str | None:
    if not html:
        return None
    soup = BeautifulSoup(html, "html.parser")
    for link in soup.find_all("link", rel=True):
        rels = [r.lower() for r in (link.get("rel") or [])]
        if any(r in ("icon", "shortcut icon", "apple-touch-icon") for r in rels):
            href = link.get("href", "")
            if href:
                return urljoin(base_url, href)
    return None


def compute_favicon_hash(content: bytes) -> int:
    encoded = base64.encodebytes(content)
    return mmh3.hash(encoded)


async def fetch_favicon(
    target: str,
    html: str = "",
    *,
    timeout: int = HTTP_TIMEOUT,
) -> FaviconResult:
    urls_to_try: list[str] = []

    linked = _find_favicon_url(html, target)
    if linked:
        urls_to_try.append(linked)

    for path in _FAVICON_PATHS:
        url = urljoin(target, path)
        if url not in urls_to_try:
            urls_to_try.append(url)

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=True,
        verify=False,
    ) as client:
        for url in urls_to_try:
            try:
                resp = await client.get(
                    url, headers={"User-Agent": UA_HONEST},
                )
                if resp.status_code != 200:
                    continue
                content_type = resp.headers.get("content-type", "").lower()
                if not resp.content or len(resp.content) < 16:
                    continue
                if "html" in content_type and len(resp.content) > 1000:
                    continue

                fav_hash = compute_favicon_hash(resp.content)
                return FaviconResult(
                    url=url,
                    hash=fav_hash,
                    size_bytes=len(resp.content),
                )
            except Exception as exc:
                logger.debug("Favicon fetch failed %s: %s", url, exc)
                continue

    return FaviconResult(error="No favicon found")
