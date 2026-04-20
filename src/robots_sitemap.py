"""Fetch and parse robots.txt and sitemap.xml for attack surface intel."""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from urllib.parse import urljoin

import httpx

from .config import HTTP_TIMEOUT
from .models import RobotsTxtResult, SitemapResult

logger = logging.getLogger(__name__)

_MAX_SITEMAP_URLS = 100
_MAX_SNIPPET = 2000


# ---------------------------------------------------------------------------
# Pure parsers (no I/O)
# ---------------------------------------------------------------------------

def parse_robots_txt(content: str) -> RobotsTxtResult:
    """Extract Disallow rules, Sitemap directives, and Crawl-delay."""
    if not content.strip():
        return RobotsTxtResult(found=False)

    disallow: list[str] = []
    sitemaps: list[str] = []
    crawl_delay: int | None = None

    for line in content.splitlines():
        line = line.strip()
        if line.startswith("#") or ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if not value:
            continue

        if key == "disallow":
            disallow.append(value)
        elif key == "sitemap":
            sitemaps.append(value)
        elif key == "crawl-delay":
            try:
                crawl_delay = int(float(value))
            except (ValueError, OverflowError):
                pass

    return RobotsTxtResult(
        found=True,
        disallow_rules=disallow,
        sitemap_urls=sitemaps,
        crawl_delay=crawl_delay,
        raw_snippet=content[:_MAX_SNIPPET],
    )


def parse_sitemap_xml(content: str) -> SitemapResult:
    """Extract URLs from a sitemap or sitemap index XML document."""
    if not content.strip():
        return SitemapResult(found=False)

    urls: list[str] = []
    nested: list[str] = []

    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return SitemapResult(found=True)

    ns = ""
    tag = root.tag
    if tag.startswith("{"):
        ns = tag.split("}")[0] + "}"

    for loc in root.iter(f"{ns}loc"):
        text = (loc.text or "").strip()
        if not text:
            continue
        parent_tag = ""
        for parent in root.iter():
            if loc in parent:
                parent_tag = parent.tag.replace(ns, "")
                break
        if parent_tag == "sitemap":
            nested.append(text)
        else:
            urls.append(text)
        if len(urls) >= _MAX_SITEMAP_URLS:
            break

    return SitemapResult(
        found=True,
        url_count=len(urls),
        urls=urls[:_MAX_SITEMAP_URLS],
        nested_sitemaps=nested,
    )


# ---------------------------------------------------------------------------
# Async fetcher
# ---------------------------------------------------------------------------

async def fetch_and_parse_robots_sitemap(
    base_url: str,
    *,
    timeout: int = HTTP_TIMEOUT,
) -> tuple[RobotsTxtResult | None, SitemapResult | None]:
    """Fetch robots.txt and sitemap.xml concurrently, parse if found."""
    import asyncio

    robots_url = urljoin(base_url.rstrip("/") + "/", "/robots.txt")
    sitemap_url = urljoin(base_url.rstrip("/") + "/", "/sitemap.xml")

    async def _fetch(url: str) -> tuple[int, str]:
        try:
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=True, verify=False,
            ) as client:
                resp = await client.get(url)
                return resp.status_code, resp.text[:50_000]
        except Exception as exc:
            logger.debug("Failed to fetch %s: %s", url, exc)
            return 0, ""

    (r_status, r_body), (s_status, s_body) = await asyncio.gather(
        _fetch(robots_url), _fetch(sitemap_url),
    )

    robots_result = None
    if r_status == 200 and r_body.strip():
        robots_result = parse_robots_txt(r_body)

    sitemap_result = None
    if s_status == 200 and s_body.strip():
        sitemap_result = parse_sitemap_xml(s_body)

    if robots_result and robots_result.sitemap_urls and not sitemap_result:
        first_sm = robots_result.sitemap_urls[0]
        sm_status, sm_body = await _fetch(first_sm)
        if sm_status == 200 and sm_body.strip():
            sitemap_result = parse_sitemap_xml(sm_body)

    return robots_result, sitemap_result
