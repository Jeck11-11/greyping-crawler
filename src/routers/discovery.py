"""Discovery endpoints (sensitive paths, tech fingerprint, JS deep-mining)."""

from __future__ import annotations

import asyncio
import logging

from bs4 import BeautifulSoup
from fastapi import APIRouter

from .._http_utils import fetch_landing_page_full, validate_target
from ..js_miner import mine_javascript
from ..models import (
    FaviconResult,
    JSIntelResult,
    NucleiResult,
    PathsReconResult,
    ReconRequest,
    SubdomainTakeoverResult,
    TechIntelResult,
)
from ..favicon import fetch_favicon
from ..nuclei_client import run_nuclei_scan
from ..path_scanner import scan_sensitive_paths
from ..postprocess import fill_not_found
from ..subdomain_takeover import scan_subdomain_takeover
from ..tech_fingerprint import fingerprint_tech

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/recon", tags=["discovery"])


@router.post("/paths", response_model=list[PathsReconResult])
async def recon_paths(request: ReconRequest) -> list[PathsReconResult]:
    """Probe each target for exposed sensitive paths (.env, .git, backups, …)."""
    targets = [validate_target(t) for t in request.targets]

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
    targets = [validate_target(t) for t in request.targets]

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
    targets = [validate_target(t) for t in request.targets]

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


@router.post("/nuclei", response_model=list[NucleiResult])
async def recon_nuclei(request: ReconRequest) -> list[NucleiResult]:
    """Run Nuclei vulnerability templates against the target(s)."""
    targets = [validate_target(t) for t in request.targets]

    async def _one(target: str) -> NucleiResult:
        try:
            return await run_nuclei_scan([target])
        except Exception as exc:
            logger.warning("Nuclei scan failed for %s: %s", target, exc)
            return NucleiResult(target=target, error=str(exc))

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results


@router.post("/favicon", response_model=list[FaviconResult])
async def recon_favicon(request: ReconRequest) -> list[FaviconResult]:
    """Fetch the favicon and compute its MurmurHash3 for Shodan/Censys pivoting."""
    targets = [validate_target(t) for t in request.targets]

    async def _one(target: str) -> FaviconResult:
        try:
            return await fetch_favicon(target, timeout=request.timeout)
        except Exception as exc:
            logger.warning("Favicon fetch failed for %s: %s", target, exc)
            return FaviconResult(error=str(exc))

    return await asyncio.gather(*(_one(t) for t in targets))


@router.post("/takeover", response_model=list[SubdomainTakeoverResult])
async def recon_takeover(request: ReconRequest) -> list[SubdomainTakeoverResult]:
    """Enumerate subdomains and check for takeover vulnerabilities."""
    from .._http_utils import normalise_target
    from urllib.parse import urlparse

    targets = [validate_target(t) for t in request.targets]

    async def _one(target: str) -> SubdomainTakeoverResult:
        hostname = urlparse(target).hostname or target
        domain = hostname.lstrip("www.")
        try:
            return await scan_subdomain_takeover(domain)
        except Exception as exc:
            logger.warning("Takeover scan failed for %s: %s", target, exc)
            from ..models import SubdomainEnumResult
            return SubdomainTakeoverResult(
                domain=domain,
                enumeration=SubdomainEnumResult(domain=domain, error=str(exc)),
                error=str(exc),
            )

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results
