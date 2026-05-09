"""Intelligence endpoints (breach databases)."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from fastapi import APIRouter

from .._http_utils import validate_target
from ..breach_checker import check_breaches
from ..c99_client import validate_email
from ..github_scanner import scan_github_secrets
from ..models import (
    BreachReconRequest,
    BreachReconResult,
    EmailValidationRequest,
    EmailValidationResult,
    GitHubSecretsReconResult,
    ReconRequest,
)
from ..postprocess import fill_not_found

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/recon", tags=["intel"])


def _domain_of(target: str) -> str:
    parsed = urlparse(target)
    return (parsed.hostname or target).lower().lstrip("www.")


@router.post("/breaches", response_model=list[BreachReconResult])
async def recon_breaches(request: BreachReconRequest) -> list[BreachReconResult]:
    """Check each target domain (plus optional seed emails) against HIBP."""
    targets = [validate_target(t) for t in request.targets]

    async def _one(target: str) -> BreachReconResult:
        domain = _domain_of(target)
        try:
            breaches = await check_breaches(domain, request.emails or [])
            return BreachReconResult(target=target, breaches=breaches)
        except Exception as exc:
            logger.warning("Breach check failed for %s: %s", target, exc)
            return BreachReconResult(target=target, error=str(exc))

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results


@router.post("/email-validation", response_model=list[EmailValidationResult])
async def recon_email_validation(
    request: EmailValidationRequest,
) -> list[EmailValidationResult]:
    """Validate email addresses via C99 API."""
    results: list[EmailValidationResult] = []

    async def _one(email: str) -> EmailValidationResult:
        try:
            data = await validate_email(email, timeout=request.timeout)
            if data is None:
                return EmailValidationResult(
                    email=email, error="Email validation unavailable"
                )
            result = EmailValidationResult(
                email=data.get("email", email),
                valid=data.get("valid"),
                disposable=data.get("disposable", False),
                role_account=data.get("role_account", False),
                free_provider=data.get("free_provider", False),
            )
            fill_not_found(result)
            return result
        except Exception as exc:
            return EmailValidationResult(email=email, error=str(exc))

    results = await asyncio.gather(*(_one(e) for e in request.emails))
    return results


@router.post("/github-secrets", response_model=list[GitHubSecretsReconResult])
async def recon_github_secrets(request: ReconRequest) -> list[GitHubSecretsReconResult]:
    """Search GitHub for leaked secrets referencing target domains."""
    targets = [validate_target(t) for t in request.targets]

    async def _one(target: str) -> GitHubSecretsReconResult:
        domain = _domain_of(target)
        try:
            result = await scan_github_secrets(domain, timeout=request.timeout)
            return GitHubSecretsReconResult(target=target, github_secrets=result)
        except Exception as exc:
            logger.warning("GitHub secret scan failed for %s: %s", target, exc)
            return GitHubSecretsReconResult(target=target, error=str(exc))

    results = await asyncio.gather(*(_one(t) for t in targets))
    for r in results:
        fill_not_found(r)
    return results
