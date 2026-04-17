"""Discovery endpoints (sensitive paths, tech fingerprint, JS deep-mining)."""

from __future__ import annotations

import asyncio
import logging

from bs4 import BeautifulSoup
from fastapi import APIRouter

from .._http_utils import fetch_landing_page_full, normalise_target
from ..js_miner import mine_javascript
from ..models import (
    JSIntelResult,
    PathsReconResult,
    ReconRequest,
    TechIntelResult,
)
from ..path_scanner import scan_sensitive_paths
from ..postprocess import fill_not_found
from ..tech_fingerprint import fingerprint_tech

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/recon", tags=["discovery"])


@router.post("/paths", response_model=list[PathsReconResult])
async def recon_paths(request: ReconRequest) -> list[PathsReconResult]:
    """Probe each target for exposed sensitive paths (.env, .git, backups, …)."""
    targets = [normalise_target(t) for t in request.targets]

    async def _one(target: str) -> PathsReconResult:
        try:
            paths = await scan_sensitive_paths(target, timeout=request.timeout)
            return PathsReconResult(target=target, sensitive_paths=paths)
        except Exception as exc:
            logger.warning("Path scan failed for %s: %s", target, exc)
            return PathsReconResult(target=target, sensitive_paths=[], error=str(exc))

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results


def _parse_meta(html: str) -> dict[str, str]:
    soup = BeautifulSoup(html or "", "html.parser")
    meta: dict[str, str] = {}
    for tag in soup.find_all("meta"):
        name = (tag.get("name") or tag.get("property") or "").lower()
        content = tag.get("content") or ""
        if name and content:
            meta[name] = content
    return meta


def _extract_script_urls_for_fingerprint(html: str) -> list[str]:
    soup = BeautifulSoup(html or "", "html.parser")
    return [tag.get("src", "") for tag in soup.find_all("script", src=True)]


@router.post("/tech", response_model=list[TechIntelResult])
async def recon_tech(request: ReconRequest) -> list[TechIntelResult]:
    """Fingerprint the web stack (CMS, JS frameworks, servers, CDNs, analytics)."""
    targets = [normalise_target(t) for t in request.targets]

    async def _one(target: str) -> TechIntelResult:
        try:
            headers, cookies, html = await fetch_landing_page_full(
                target, timeout=request.timeout,
            )
            meta = _parse_meta(html)
            scripts = _extract_script_urls_for_fingerprint(html)
            techs = fingerprint_tech(
                html=html,
                headers=headers,
                cookies=cookies,
                script_urls=scripts,
                meta=meta,
            )
            return TechIntelResult(target=target, technologies=techs)
        except Exception as exc:
            logger.warning("Tech fingerprint failed for %s: %s", target, exc)
            return TechIntelResult(target=target, technologies=[], error=str(exc))

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results


@router.post("/js-intel", response_model=list[JSIntelResult])
async def recon_js_intel(request: ReconRequest) -> list[JSIntelResult]:
    """Mine the target's JavaScript bundles for endpoints, internal hosts, sourcemaps."""
    targets = [normalise_target(t) for t in request.targets]

    async def _one(target: str) -> JSIntelResult:
        try:
            _headers, _cookies, html = await fetch_landing_page_full(
                target, timeout=request.timeout,
            )
            return await mine_javascript(target, html, timeout=request.timeout)
        except Exception as exc:
            logger.warning("JS intel failed for %s: %s", target, exc)
            return JSIntelResult(target=target, scripts_scanned=0, error=str(exc))

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results
