"""Passive-intel endpoints (DNS, CT logs, RDAP, Wayback).

These endpoints never touch the target. All data is sourced from public
third-party services — safe to run against targets behind a WAF/IDS.
"""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from fastapi import APIRouter

from .._http_utils import validate_target
from ..models import (
    CTResult,
    DNSResult,
    EmailSecurityResult,
    RDAPResult,
    ReconRequest,
    WaybackResult,
)
from ..passive_intel import (
    query_ct_logs,
    query_dns,
    query_email_security,
    query_rdap,
    query_wayback,
)
from ..postprocess import fill_not_found

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/recon", tags=["passive"])


def _domain_of(target: str) -> str:
    parsed = urlparse(target)
    return (parsed.hostname or target).lower().lstrip("www.")


@router.post("/dns", response_model=list[DNSResult])
async def recon_dns(request: ReconRequest) -> list[DNSResult]:
    """Resolve A / AAAA records via the system resolver. No target traffic."""
    targets = [validate_target(t) for t in request.targets]
    results = await asyncio.gather(
        *(query_dns(_domain_of(t), timeout=request.timeout) for t in targets),
    )
    for r in results:
        fill_not_found(r)
    return results


@router.post("/ct", response_model=list[CTResult])
async def recon_ct(request: ReconRequest) -> list[CTResult]:
    """Pull every cert ever issued for the target's apex via crt.sh."""
    targets = [validate_target(t) for t in request.targets]
    results = await asyncio.gather(
        *(query_ct_logs(_domain_of(t), timeout=request.timeout) for t in targets),
    )
    for r in results:
        fill_not_found(r)
    return results


@router.post("/whois", response_model=list[RDAPResult])
async def recon_whois(request: ReconRequest) -> list[RDAPResult]:
    """Look up registrar metadata via RDAP (rdap.org)."""
    targets = [validate_target(t) for t in request.targets]
    results = await asyncio.gather(
        *(query_rdap(_domain_of(t), timeout=request.timeout) for t in targets),
    )
    for r in results:
        fill_not_found(r)
    return results


@router.post("/wayback", response_model=list[WaybackResult])
async def recon_wayback(request: ReconRequest) -> list[WaybackResult]:
    """Ask archive.org for snapshot history."""
    targets = [validate_target(t) for t in request.targets]
    results = await asyncio.gather(
        *(query_wayback(_domain_of(t), timeout=request.timeout) for t in targets),
    )
    for r in results:
        fill_not_found(r)
    return results


@router.post("/email-security", response_model=list[EmailSecurityResult])
async def recon_email_security(request: ReconRequest) -> list[EmailSecurityResult]:
    """Audit email authentication (SPF/DKIM/DMARC) via DNS lookups."""
    targets = [validate_target(t) for t in request.targets]
    results: list[EmailSecurityResult] = []

    for t in targets:
        domain = _domain_of(t)
        try:
            dns_result = await query_dns(domain, timeout=request.timeout)
            mx_records = dns_result.mx_records if dns_result else None
            result = await query_email_security(
                domain, mx_records=mx_records, timeout=request.timeout
            )
            fill_not_found(result)
            results.append(result)
        except Exception as exc:
            results.append(EmailSecurityResult(domain=domain, error=str(exc)))

    return results
