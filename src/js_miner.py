"""JavaScript bundle deep-mining.

Fetches `<script src>` files referenced by a page and extracts:
  * API endpoints (paths beginning with /api, /v1, /graphql, etc.)
  * Internal hostnames (*.internal, *.local, *.corp, 10.x private IPs)
  * Source-map URLs, and their recovered source file list if accessible
"""

from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urljoin, urlparse

import httpx
from bs4 import BeautifulSoup

from .config import JS_FETCH_CONCURRENCY, JS_MINE_TIMEOUT, MAX_SCRIPTS, UA_HONEST
from .models import JSIntelResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_ENDPOINT_PATTERNS = [
    re.compile(r"""['"](/api/v?\d*/[^\s'"<>]{2,200})['"]"""),
    re.compile(r"""['"](/graphql[^\s'"<>]*)['"]"""),
    re.compile(r"""baseURL\s*[:=]\s*['"]([^'"]+)['"]"""),
    re.compile(r"""(?:API_URL|apiUrl|API_BASE|apiBase)\s*[:=]\s*['"]([^'"]+)['"]"""),
    re.compile(r"""['"](https?://api\.[a-z0-9.-]+(?:/[^\s'"<>]{0,200})?)['"]"""),
]

_INTERNAL_HOST_PATTERNS = [
    re.compile(r"""['"](https?://[a-z0-9-]+\.internal(?::\d+)?(?:/[^\s'"<>]{0,200})?)['"]"""),
    re.compile(r"""['"](https?://[a-z0-9-]+\.(?:local|corp|lan)(?::\d+)?(?:/[^\s'"<>]{0,200})?)['"]"""),
    re.compile(r"""['"](https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s'"<>]{0,200})?)['"]"""),
    re.compile(r"""['"](https?://192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s'"<>]{0,200})?)['"]"""),
    re.compile(r"""['"](https?://172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s'"<>]{0,200})?)['"]"""),
]

_SOURCEMAP_RE = re.compile(r"(?://|/\*)[#@]\s*sourceMappingURL=([^\s*]+)")


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

_UA = f"{UA_HONEST} (JS-Intel)"


async def _fetch_text(client: httpx.AsyncClient, url: str) -> str:
    try:
        r = await client.get(url, headers={"User-Agent": _UA})
        if r.status_code == 200 and len(r.content) < 5_000_000:
            return r.text
    except Exception as exc:
        logger.debug("JS fetch failed %s: %s", url, exc)
    return ""


async def _fetch_json(client: httpx.AsyncClient, url: str) -> dict | None:
    try:
        r = await client.get(url, headers={"User-Agent": _UA})
        if r.status_code == 200 and "json" in r.headers.get("content-type", "").lower():
            return r.json()
        # Source maps often served as application/octet-stream
        if r.status_code == 200 and r.content[:1] == b"{":
            return r.json()
    except Exception as exc:
        logger.debug("Sourcemap fetch failed %s: %s", url, exc)
    return None


# ---------------------------------------------------------------------------
# Discovery helpers
# ---------------------------------------------------------------------------

def extract_script_urls(html: str, base_url: str) -> list[str]:
    """Return absolute URLs for every <script src> on the page."""
    soup = BeautifulSoup(html or "", "html.parser")
    urls: list[str] = []
    for tag in soup.find_all("script", src=True):
        src = tag.get("src") or ""
        if not src or src.startswith(("data:", "javascript:", "about:")):
            continue
        urls.append(urljoin(base_url, src))
    # Dedupe while preserving order
    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def extract_endpoints(js: str) -> list[str]:
    found: set[str] = set()
    for pat in _ENDPOINT_PATTERNS:
        for m in pat.findall(js):
            if len(m) <= 500:
                found.add(m)
    return sorted(found)


def extract_internal_hosts(js: str) -> list[str]:
    found: set[str] = set()
    for pat in _INTERNAL_HOST_PATTERNS:
        for m in pat.findall(js):
            found.add(m)
    return sorted(found)


def extract_sourcemap_url(js: str, script_url: str) -> str | None:
    m = _SOURCEMAP_RE.search(js)
    if not m:
        return None
    return urljoin(script_url, m.group(1).strip())


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def mine_javascript(
    target: str,
    html: str,
    *,
    timeout: int = JS_MINE_TIMEOUT,
    max_scripts: int = MAX_SCRIPTS,
) -> JSIntelResult:
    """Fetch every <script src> on *target*'s landing page and mine for intel."""
    script_urls = extract_script_urls(html, target)[:max_scripts]

    # Only follow scripts on the same registrable hostname (skip huge third-
    # party CDNs — they rarely leak useful endpoints of the target).
    target_host = (urlparse(target).hostname or "").lower().lstrip("www.")
    own_scripts = [
        u for u in script_urls
        if (urlparse(u).hostname or "").lower().lstrip("www.").endswith(target_host)
    ] or script_urls  # fall back to all if none match

    api_endpoints: set[str] = set()
    internal_hosts: set[str] = set()
    sourcemaps: list[str] = []
    recovered: list[str] = []
    scanned = 0
    sem = asyncio.Semaphore(JS_FETCH_CONCURRENCY)

    async def _mine_one(client: httpx.AsyncClient, url: str):
        async with sem:
            js = await _fetch_text(client, url)
        if not js:
            return None
        return (
            extract_endpoints(js),
            extract_internal_hosts(js),
            extract_sourcemap_url(js, url),
        )

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            verify=False,
        ) as client:
            results = await asyncio.gather(
                *(_mine_one(client, u) for u in own_scripts),
                return_exceptions=True,
            )
            for r in results:
                if r is None or isinstance(r, Exception):
                    continue
                eps, hosts, sm = r
                scanned += 1
                api_endpoints.update(eps)
                internal_hosts.update(hosts)
                if sm:
                    sourcemaps.append(sm)

            # Opportunistically fetch sourcemaps (they're often left online in prod)
            for sm in sourcemaps:
                data = await _fetch_json(client, sm)
                if isinstance(data, dict):
                    for s in data.get("sources") or []:
                        recovered.append(s)
    except Exception as exc:
        logger.warning("JS mining failed for %s: %s", target, exc)
        return JSIntelResult(target=target, scripts_scanned=scanned, error=str(exc))

    return JSIntelResult(
        target=target,
        scripts_scanned=scanned,
        api_endpoints=sorted(api_endpoints),
        internal_hosts=sorted(internal_hosts),
        sourcemaps_found=sourcemaps,
        recovered_source_files=sorted(set(recovered))[:500],
    )
