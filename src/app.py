"""FastAPI application – OSINT Reconnaissance API."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .breach_checker import check_breaches
from .crawler import crawl_domain
from .models import (
    ContactInfo,
    DomainResult,
    ScanRequest,
    ScanResponse,
)

logger = logging.getLogger("osint_api")
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

app = FastAPI(
    title="GreyPing OSINT Reconnaissance API",
    description=(
        "Real-time website scanning and data extraction API. "
        "Crawls domains to extract contacts, links, exposed secrets, "
        "and checks against breach databases."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _extract_domain(url: str) -> str:
    """Return the bare domain from a URL."""
    parsed = urlparse(url)
    return (parsed.hostname or url).lower().lstrip("www.")


def _normalise_target(raw: str) -> str:
    """Ensure the target has a scheme so urlparse works correctly."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    return raw


async def _scan_single_target(
    target: str,
    request: ScanRequest,
) -> DomainResult:
    """Run the full scan pipeline for a single target domain."""
    domain = _extract_domain(target)
    started = datetime.now(timezone.utc).isoformat()

    try:
        pages = await crawl_domain(
            target,
            render_js=request.render_js,
            follow_redirects=request.follow_redirects,
            max_depth=request.max_depth,
            timeout=request.timeout,
        )
    except Exception as exc:
        logger.exception("Crawl failed for %s", target)
        return DomainResult(
            target=target,
            scan_started_at=started,
            scan_finished_at=datetime.now(timezone.utc).isoformat(),
            error=str(exc),
        )

    # Aggregate contacts, links, and secrets across all pages
    all_emails: set[str] = set()
    all_phones: set[str] = set()
    all_socials: set[str] = set()
    internal_links: set[str] = set()
    external_links: set[str] = set()
    all_secrets = []

    for page in pages:
        all_emails.update(page.contacts.emails)
        all_phones.update(page.contacts.phone_numbers)
        all_socials.update(page.contacts.social_profiles)
        for link in page.links:
            if link.link_type == "internal":
                internal_links.add(link.url)
            else:
                external_links.add(link.url)
        all_secrets.extend(page.secrets)

    # Breach checks
    breaches = []
    if request.check_breaches:
        try:
            breaches = await check_breaches(domain, list(all_emails))
        except Exception as exc:
            logger.warning("Breach check failed for %s: %s", domain, exc)

    finished = datetime.now(timezone.utc).isoformat()

    return DomainResult(
        target=target,
        scan_started_at=started,
        scan_finished_at=finished,
        pages_scanned=len(pages),
        pages=pages,
        contacts=ContactInfo(
            emails=sorted(all_emails),
            phone_numbers=sorted(all_phones),
            social_profiles=sorted(all_socials),
        ),
        internal_links=sorted(internal_links),
        external_links=sorted(external_links),
        secrets=all_secrets,
        breaches=breaches,
        metadata={
            "domain": domain,
            "render_js": request.render_js,
            "max_depth": request.max_depth,
        },
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: ScanRequest) -> ScanResponse:
    """Perform a batch OSINT scan across one or more target domains."""
    scan_id = uuid.uuid4().hex
    started = datetime.now(timezone.utc).isoformat()

    targets = [_normalise_target(t) for t in request.targets]

    # Run all domain scans concurrently
    tasks = [_scan_single_target(t, request) for t in targets]
    domain_results: list[DomainResult] = await asyncio.gather(*tasks)

    finished = datetime.now(timezone.utc).isoformat()

    total_pages = sum(r.pages_scanned for r in domain_results)
    total_secrets = sum(len(r.secrets) for r in domain_results)
    total_breaches = sum(len(r.breaches) for r in domain_results)

    # Determine overall status
    errors = [r for r in domain_results if r.error]
    if len(errors) == len(domain_results):
        status = "failed"
    elif errors:
        status = "partial"
    else:
        status = "completed"

    return ScanResponse(
        scan_id=scan_id,
        status=status,
        started_at=started,
        finished_at=finished,
        total_targets=len(targets),
        total_pages_scanned=total_pages,
        total_secrets_found=total_secrets,
        total_breaches_found=total_breaches,
        results=domain_results,
    )


@app.post("/scan/quick")
async def quick_scan(request: ScanRequest) -> ScanResponse:
    """Quick scan – static fetch only, depth 0, no breach check."""
    request.render_js = False
    request.max_depth = 0
    request.check_breaches = False
    return await scan(request)
