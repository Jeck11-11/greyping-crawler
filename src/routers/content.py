"""Content-focused endpoints (crawl, contacts, links, secrets, IoC)."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urlparse

from fastapi import APIRouter

from .._http_utils import normalise_target
from ..crawler import crawl_domain
from ..models import (
    ContactReconResult,
    CrawlReconRequest,
    CrawlReconResult,
    EmailFinding,
    ExternalLinkFinding,
    IoCReconResult,
    LinkReconResult,
    PhoneFinding,
    SecretsReconResult,
    SocialFinding,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/recon", tags=["content"])


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
    try:
        host = (urlparse(url).hostname or "").lower().lstrip("www.")
        return _SOCIAL_PLATFORM_MAP.get(host, "")
    except Exception:
        return ""


async def _crawl(target: str, request: CrawlReconRequest):
    return await crawl_domain(
        target,
        render_js=request.render_js,
        follow_redirects=request.follow_redirects,
        max_depth=request.max_depth,
        timeout=request.timeout,
    )


@router.post("/crawl", response_model=list[CrawlReconResult])
async def recon_crawl(request: CrawlReconRequest) -> list[CrawlReconResult]:
    """Crawl each target and return raw per-page results."""
    targets = [normalise_target(t) for t in request.targets]

    async def _one(target: str) -> CrawlReconResult:
        try:
            pages = await _crawl(target, request)
            return CrawlReconResult(
                target=target, pages_scanned=len(pages), pages=pages,
            )
        except Exception as exc:
            logger.warning("Crawl failed for %s: %s", target, exc)
            return CrawlReconResult(target=target, error=str(exc))

    return await asyncio.gather(*(_one(t) for t in targets))


@router.post("/contacts", response_model=list[ContactReconResult])
async def recon_contacts(request: CrawlReconRequest) -> list[ContactReconResult]:
    """Crawl each target and aggregate contact data with per-page provenance."""
    targets = [normalise_target(t) for t in request.targets]

    async def _one(target: str) -> ContactReconResult:
        try:
            pages = await _crawl(target, request)
            email_sources: dict[str, list[str]] = {}
            phone_sources: dict[str, list[str]] = {}
            social_sources: dict[str, list[str]] = {}
            for page in pages:
                for e in page.contacts.emails:
                    email_sources.setdefault(e, []).append(page.url)
                for p in page.contacts.phone_numbers:
                    phone_sources.setdefault(p, []).append(page.url)
                for s in page.contacts.social_profiles:
                    social_sources.setdefault(s, []).append(page.url)

            return ContactReconResult(
                target=target,
                emails=[
                    EmailFinding(email=e, found_on=sorted(set(urls)))
                    for e, urls in sorted(email_sources.items())
                ],
                phone_numbers=[
                    PhoneFinding(phone=p, found_on=sorted(set(urls)))
                    for p, urls in sorted(phone_sources.items())
                ],
                social_profiles=[
                    SocialFinding(
                        url=s,
                        platform=_detect_platform(s),
                        found_on=sorted(set(urls)),
                    )
                    for s, urls in sorted(social_sources.items())
                ],
            )
        except Exception as exc:
            logger.warning("Contact scan failed for %s: %s", target, exc)
            return ContactReconResult(target=target, error=str(exc))

    return await asyncio.gather(*(_one(t) for t in targets))


@router.post("/links", response_model=list[LinkReconResult])
async def recon_links(request: CrawlReconRequest) -> list[LinkReconResult]:
    """Crawl each target and return internal + external link lists."""
    targets = [normalise_target(t) for t in request.targets]

    async def _one(target: str) -> LinkReconResult:
        try:
            pages = await _crawl(target, request)
            internal: set[str] = set()
            ext: dict[str, dict] = {}
            for page in pages:
                for link in page.links:
                    if link.link_type == "internal":
                        internal.add(link.url)
                    else:
                        entry = ext.setdefault(
                            link.url,
                            {"anchor_text": link.anchor_text, "found_on": []},
                        )
                        entry["found_on"].append(page.url)

            return LinkReconResult(
                target=target,
                internal_links=sorted(internal),
                external_links=[
                    ExternalLinkFinding(
                        url=u,
                        anchor_text=d["anchor_text"],
                        found_on=sorted(set(d["found_on"])),
                    )
                    for u, d in sorted(ext.items())
                ],
            )
        except Exception as exc:
            logger.warning("Link scan failed for %s: %s", target, exc)
            return LinkReconResult(target=target, error=str(exc))

    return await asyncio.gather(*(_one(t) for t in targets))


@router.post("/secrets", response_model=list[SecretsReconResult])
async def recon_secrets(request: CrawlReconRequest) -> list[SecretsReconResult]:
    """Crawl each target and return exposed secrets across all pages."""
    targets = [normalise_target(t) for t in request.targets]

    async def _one(target: str) -> SecretsReconResult:
        try:
            pages = await _crawl(target, request)
            secrets = []
            for page in pages:
                secrets.extend(page.secrets)
            return SecretsReconResult(target=target, secrets=secrets)
        except Exception as exc:
            logger.warning("Secret scan failed for %s: %s", target, exc)
            return SecretsReconResult(target=target, error=str(exc))

    return await asyncio.gather(*(_one(t) for t in targets))


@router.post("/ioc", response_model=list[IoCReconResult])
async def recon_ioc(request: CrawlReconRequest) -> list[IoCReconResult]:
    """Crawl each target and return deduplicated indicator-of-compromise findings."""
    targets = [normalise_target(t) for t in request.targets]

    async def _one(target: str) -> IoCReconResult:
        try:
            pages = await _crawl(target, request)
            seen: set[tuple[str, str]] = set()
            iocs = []
            for page in pages:
                for ioc in page.ioc_findings:
                    key = (ioc.ioc_type, ioc.evidence)
                    if key not in seen:
                        seen.add(key)
                        iocs.append(ioc)
            return IoCReconResult(target=target, ioc_findings=iocs)
        except Exception as exc:
            logger.warning("IoC scan failed for %s: %s", target, exc)
            return IoCReconResult(target=target, error=str(exc))

    return await asyncio.gather(*(_one(t) for t in targets))
