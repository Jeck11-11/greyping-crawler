"""Network-level reconnaissance endpoints (SSL, headers, cookies)."""

from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter

from urllib.parse import urlparse

from .._http_utils import fetch_landing_page, validate_target
from ..cookie_checker import analyze_cookies
from ..models import (
    CookiesReconResult,
    HeadersReconResult,
    PortScanResult,
    ReconRequest,
    SecurityHeadersResult,
    SSLCertResult,
    SSLReconResult,
)
from ..port_scanner import scan_ports
from ..security_headers import analyze_headers
from ..postprocess import fill_not_found
from ..ssl_checker import check_ssl

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/recon", tags=["network"])


@router.post("/ssl", response_model=list[SSLReconResult])
async def recon_ssl(request: ReconRequest) -> list[SSLReconResult]:
    """Grade the TLS certificate for each target."""
    targets = [validate_target(t) for t in request.targets]

    async def _one(target: str) -> SSLReconResult:
        try:
            ssl = await check_ssl(target, timeout=request.timeout)
            return SSLReconResult(target=target, ssl=ssl)
        except Exception as exc:
            logger.warning("SSL check failed for %s: %s", target, exc)
            return SSLReconResult(
                target=target,
                ssl=SSLCertResult(is_valid=False, issues=[f"Check failed: {exc}"]),
                error=str(exc),
            )

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results


@router.post("/headers", response_model=list[HeadersReconResult])
async def recon_headers(request: ReconRequest) -> list[HeadersReconResult]:
    """Audit security response headers on the landing page of each target."""
    targets = [validate_target(t) for t in request.targets]

    async def _one(target: str) -> HeadersReconResult:
        try:
            headers, _cookies = await fetch_landing_page(target, timeout=request.timeout)
            return HeadersReconResult(target=target, headers=analyze_headers(headers))
        except Exception as exc:
            logger.warning("Header audit failed for %s: %s", target, exc)
            return HeadersReconResult(
                target=target,
                headers=SecurityHeadersResult(),
                error=str(exc),
            )

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results


@router.post("/cookies", response_model=list[CookiesReconResult])
async def recon_cookies(request: ReconRequest) -> list[CookiesReconResult]:
    """Audit cookies set by each target's landing page."""
    targets = [validate_target(t) for t in request.targets]

    async def _one(target: str) -> CookiesReconResult:
        try:
            _headers, cookies = await fetch_landing_page(target, timeout=request.timeout)
            return CookiesReconResult(target=target, cookies=analyze_cookies(cookies))
        except Exception as exc:
            logger.warning("Cookie audit failed for %s: %s", target, exc)
            return CookiesReconResult(target=target, cookies=[], error=str(exc))

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results


@router.post("/ports", response_model=list[PortScanResult])
async def recon_ports(request: ReconRequest) -> list[PortScanResult]:
    """Scan the top TCP ports for each target."""
    targets = [validate_target(t) for t in request.targets]

    async def _one(target: str) -> PortScanResult:
        hostname = urlparse(target).hostname or target
        try:
            return await scan_ports(hostname)
        except Exception as exc:
            logger.warning("Port scan failed for %s: %s", target, exc)
            return PortScanResult(target=hostname, error=str(exc))

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results
