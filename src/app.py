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
    EmailFinding,
    ExternalLinkFinding,
    PhoneFinding,
    ScanRequest,
    ScanResponse,
    SocialFinding,
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


_SOCIAL_PLATFORM_MAP = {
    "twitter.com": "Twitter", "x.com": "Twitter/X",
    "facebook.com": "Facebook", "fb.com": "Facebook",
    "linkedin.com": "LinkedIn", "instagram.com": "Instagram",
    "github.com": "GitHub", "youtube.com": "YouTube",
    "tiktok.com": "TikTok", "pinterest.com": "Pinterest",
    "reddit.com": "Reddit", "t.me": "Telegram",
    "mastodon.social": "Mastodon",
}


def _detect_platform(url: str) -> str:
    """Return the platform name for a social URL, or empty string."""
    try:
        host = (urlparse(url).hostname or "").lower().lstrip("www.")
        return _SOCIAL_PLATFORM_MAP.get(host, "")
    except Exception:
        return ""


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

    # Aggregate contacts, links, and secrets across all pages,
    # tracking which page URL each finding came from.
    email_sources: dict[str, list[str]] = {}
    phone_sources: dict[str, list[str]] = {}
    social_sources: dict[str, list[str]] = {}
    internal_links: set[str] = set()
    ext_link_sources: dict[str, dict] = {}   # url -> {anchor_text, found_on}
    all_secrets = []

    for page in pages:
        page_url = page.url
        for email in page.contacts.emails:
            email_sources.setdefault(email, []).append(page_url)
        for phone in page.contacts.phone_numbers:
            phone_sources.setdefault(phone, []).append(page_url)
        for social in page.contacts.social_profiles:
            social_sources.setdefault(social, []).append(page_url)
        for link in page.links:
            if link.link_type == "internal":
                internal_links.add(link.url)
            else:
                entry = ext_link_sources.setdefault(
                    link.url, {"anchor_text": link.anchor_text, "found_on": []}
                )
                entry["found_on"].append(page_url)
        all_secrets.extend(page.secrets)

    # Build provenance-tracked lists
    email_findings = [
        EmailFinding(email=e, found_on=sorted(set(urls)))
        for e, urls in sorted(email_sources.items())
    ]
    phone_findings = [
        PhoneFinding(phone=p, found_on=sorted(set(urls)))
        for p, urls in sorted(phone_sources.items())
    ]
    social_findings = [
        SocialFinding(url=s, platform=_detect_platform(s), found_on=sorted(set(urls)))
        for s, urls in sorted(social_sources.items())
    ]
    ext_link_findings = [
        ExternalLinkFinding(
            url=u, anchor_text=d["anchor_text"], found_on=sorted(set(d["found_on"])),
        )
        for u, d in sorted(ext_link_sources.items())
    ]

    # Flat contact list (backwards-compatible)
    flat_contacts = ContactInfo(
        emails=sorted(email_sources),
        phone_numbers=sorted(phone_sources),
        social_profiles=sorted(social_sources),
    )

    # Breach checks
    breaches = []
    if request.check_breaches:
        try:
            breaches = await check_breaches(domain, list(email_sources))
        except Exception as exc:
            logger.warning("Breach check failed for %s: %s", domain, exc)

    finished = datetime.now(timezone.utc).isoformat()

    return DomainResult(
        target=target,
        scan_started_at=started,
        scan_finished_at=finished,
        pages_scanned=len(pages),
        pages=pages,
        contacts=flat_contacts,
        emails=email_findings,
        phone_numbers=phone_findings,
        social_profiles=social_findings,
        internal_links=sorted(internal_links),
        external_links=ext_link_findings,
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
