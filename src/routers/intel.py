"""Intelligence endpoints (breach databases)."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from fastapi import APIRouter

from .._http_utils import normalise_target
from ..breach_checker import check_breaches
from ..models import BreachReconRequest, BreachReconResult

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/recon", tags=["intel"])


def _domain_of(target: str) -> str:
    parsed = urlparse(target)
    return (parsed.hostname or target).lower().lstrip("www.")


@router.post("/breaches", response_model=list[BreachReconResult])
async def recon_breaches(request: BreachReconRequest) -> list[BreachReconResult]:
    """Check each target domain (plus optional seed emails) against HIBP."""
    targets = [normalise_target(t) for t in request.targets]

    async def _one(target: str) -> BreachReconResult:
        domain = _domain_of(target)
        try:
            breaches = await check_breaches(domain, request.emails or [])
            return BreachReconResult(target=target, breaches=breaches)
        except Exception as exc:
            logger.warning("Breach check failed for %s: %s", target, exc)
            return BreachReconResult(target=target, error=str(exc))

    return await asyncio.gather(*(_one(t) for t in targets))
