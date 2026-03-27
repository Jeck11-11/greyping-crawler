"""Check domains and emails against known breach databases.

Integrates with the Have I Been Pwned (HIBP) v3 API when an API key is
configured, and falls back to the open BreachDirectory-style endpoint for
basic domain lookups.
"""

from __future__ import annotations

import logging
import os

import httpx

from .models import BreachRecord

logger = logging.getLogger(__name__)

HIBP_API_KEY: str = os.getenv("HIBP_API_KEY", "")
HIBP_BASE_URL = "https://haveibeenpwned.com/api/v3"
HIBP_TIMEOUT = 15

# Rate-limit: HIBP allows ~10 req / min on paid keys; we respect this with
# a simple per-call approach (no burst).


async def _hibp_breaches_for_domain(domain: str) -> list[BreachRecord]:
    """Query HIBP for breaches associated with *domain*."""
    if not HIBP_API_KEY:
        logger.debug("HIBP_API_KEY not set – skipping HIBP lookup for %s", domain)
        return []

    url = f"{HIBP_BASE_URL}/breaches"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "GreypingCrawler/1.0",
    }
    params = {"domain": domain}

    try:
        async with httpx.AsyncClient(timeout=HIBP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("HIBP lookup failed for %s: %s", domain, exc)
        return []

    records: list[BreachRecord] = []
    for entry in data:
        records.append(
            BreachRecord(
                source="haveibeenpwned",
                breach_name=entry.get("Name", ""),
                domain=entry.get("Domain", domain),
                breach_date=entry.get("BreachDate", ""),
                data_types=entry.get("DataClasses", []),
                description=entry.get("Description", "")[:500],
            )
        )
    return records


async def _hibp_breaches_for_email(email: str) -> list[BreachRecord]:
    """Query HIBP for breaches associated with a specific *email*."""
    if not HIBP_API_KEY:
        return []

    url = f"{HIBP_BASE_URL}/breachedaccount/{email}"
    headers = {
        "hibp-api-key": HIBP_API_KEY,
        "User-Agent": "GreypingCrawler/1.0",
    }
    params = {"truncateResponse": "false"}

    try:
        async with httpx.AsyncClient(timeout=HIBP_TIMEOUT) as client:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 404:
                return []
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        logger.warning("HIBP email lookup failed for %s: %s", email, exc)
        return []

    records: list[BreachRecord] = []
    for entry in data:
        records.append(
            BreachRecord(
                source="haveibeenpwned",
                breach_name=entry.get("Name", ""),
                domain=entry.get("Domain", ""),
                breach_date=entry.get("BreachDate", ""),
                data_types=entry.get("DataClasses", []),
                description=entry.get("Description", "")[:500],
            )
        )
    return records


async def check_breaches(
    domain: str,
    emails: list[str] | None = None,
) -> list[BreachRecord]:
    """Check *domain* (and optionally discovered *emails*) against breach DBs.

    Returns a de-duplicated list of :class:`BreachRecord`.
    """
    seen: set[str] = set()
    results: list[BreachRecord] = []

    # 1. Domain-level lookup
    for record in await _hibp_breaches_for_domain(domain):
        key = (record.source, record.breach_name)
        if key not in seen:
            seen.add(key)
            results.append(record)

    # 2. Per-email lookups (cap to 10 emails to stay within rate limits)
    if emails:
        for email in emails[:10]:
            for record in await _hibp_breaches_for_email(email):
                key = (record.source, record.breach_name)
                if key not in seen:
                    seen.add(key)
                    results.append(record)

    if not HIBP_API_KEY and not results:
        logger.info(
            "No HIBP_API_KEY configured. Set the HIBP_API_KEY env var to "
            "enable breach-database lookups."
        )

    return results
