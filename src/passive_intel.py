"""Passive OSINT sources.

Every function here queries a *third-party* source and touches nothing
belonging to the target. That makes these calls safe to run against a
target that has a WAF/IDS/bot-manager – the target's edge sees no
traffic from us.

Sources:
  * DNS          – stdlib resolver for A / AAAA records
  * CT logs      – https://crt.sh
  * RDAP         – https://rdap.org (JSON-over-HTTPS, RFC 7482-7484)
  * Wayback      – https://archive.org

All functions return a Pydantic result with ``error`` set on failure
instead of raising, matching the pattern used by the active detectors.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import Any

import httpx

from .models import CTResult, DNSResult, RDAPResult, WaybackResult

logger = logging.getLogger(__name__)

_UA = "GreypingCrawler/1.0 (passive-intel)"


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

async def query_dns(domain: str, *, timeout: int = 10) -> DNSResult:
    """Resolve A and AAAA records via the system resolver."""
    loop = asyncio.get_running_loop()

    def _resolve(family: int) -> list[str]:
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
            return sorted({info[4][0] for info in infos})
        except socket.gaierror:
            return []

    try:
        a_task = loop.run_in_executor(None, _resolve, socket.AF_INET)
        aaaa_task = loop.run_in_executor(None, _resolve, socket.AF_INET6)
        a_records, aaaa_records = await asyncio.wait_for(
            asyncio.gather(a_task, aaaa_task),
            timeout=timeout,
        )
        return DNSResult(
            domain=domain,
            a_records=a_records,
            aaaa_records=aaaa_records,
        )
    except asyncio.TimeoutError:
        return DNSResult(domain=domain, error="DNS resolution timed out")
    except Exception as exc:
        logger.warning("DNS lookup failed for %s: %s", domain, exc)
        return DNSResult(domain=domain, error=str(exc))


# ---------------------------------------------------------------------------
# Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------

async def query_ct_logs(domain: str, *, timeout: int = 15) -> CTResult:
    """Query crt.sh for every cert ever issued for *domain* (incl. subdomains).

    Returns deduped subdomains + unique issuer names.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": _UA, "Accept": "application/json"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            if resp.status_code != 200:
                return CTResult(
                    domain=domain,
                    error=f"crt.sh returned HTTP {resp.status_code}",
                )
            data = resp.json()

        subdomains: set[str] = set()
        issuers: set[str] = set()
        for entry in data or []:
            name_value = entry.get("name_value") or ""
            for host in name_value.splitlines():
                host = host.strip().lower().lstrip("*.")
                if host and host.endswith(domain.lower()):
                    subdomains.add(host)
            cn = (entry.get("common_name") or "").strip().lower().lstrip("*.")
            if cn and cn.endswith(domain.lower()):
                subdomains.add(cn)
            issuer = (entry.get("issuer_name") or "").strip()
            if issuer:
                issuers.add(issuer)

        return CTResult(
            domain=domain,
            subdomains=sorted(subdomains),
            issuers=sorted(issuers),
            certificates_seen=len(data or []),
        )
    except Exception as exc:
        logger.warning("CT log query failed for %s: %s", domain, exc)
        return CTResult(domain=domain, error=str(exc))


# ---------------------------------------------------------------------------
# RDAP (registrar metadata)
# ---------------------------------------------------------------------------

def _rdap_event_date(events: list[dict[str, Any]], action: str) -> str:
    for ev in events or []:
        if (ev.get("eventAction") or "").lower() == action:
            return ev.get("eventDate") or ""
    return ""


def _rdap_registrar(entities: list[dict[str, Any]]) -> str:
    for ent in entities or []:
        roles = [r.lower() for r in (ent.get("roles") or [])]
        if "registrar" not in roles:
            continue
        for item in ent.get("vcardArray", [None, []])[1]:
            if isinstance(item, list) and len(item) >= 4 and item[0] == "fn":
                return str(item[3])
    return ""


def _rdap_nameservers(nameservers: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for ns in nameservers or []:
        name = (ns.get("ldhName") or ns.get("unicodeName") or "").lower()
        if name:
            out.append(name)
    return sorted(set(out))


async def query_rdap(domain: str, *, timeout: int = 15) -> RDAPResult:
    """Look up registrar metadata via rdap.org."""
    url = f"https://rdap.org/domain/{domain}"
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": _UA, "Accept": "application/rdap+json"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(url)
            if resp.status_code == 404:
                return RDAPResult(domain=domain, error="Domain not found in RDAP")
            if resp.status_code != 200:
                return RDAPResult(
                    domain=domain,
                    error=f"RDAP returned HTTP {resp.status_code}",
                )
            data = resp.json()

        return RDAPResult(
            domain=domain,
            registrar=_rdap_registrar(data.get("entities") or []),
            created=_rdap_event_date(data.get("events") or [], "registration"),
            expires=_rdap_event_date(data.get("events") or [], "expiration"),
            name_servers=_rdap_nameservers(data.get("nameservers") or []),
            status=[s for s in (data.get("status") or []) if isinstance(s, str)],
        )
    except Exception as exc:
        logger.warning("RDAP lookup failed for %s: %s", domain, exc)
        return RDAPResult(domain=domain, error=str(exc))


# ---------------------------------------------------------------------------
# Wayback Machine
# ---------------------------------------------------------------------------

def _format_wayback_ts(ts: str) -> str:
    if len(ts) >= 8 and ts.isdigit():
        return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}"
    return ts


async def query_wayback(domain: str, *, timeout: int = 15) -> WaybackResult:
    """Ask archive.org what it knows about *domain*."""
    cdx_url = (
        f"https://web.archive.org/cdx/search/cdx?url={domain}"
        "&output=json&limit=50&from=20000101"
    )
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": _UA, "Accept": "application/json"},
            follow_redirects=True,
        ) as client:
            resp = await client.get(cdx_url)
            if resp.status_code != 200:
                return WaybackResult(
                    domain=domain,
                    error=f"Wayback CDX returned HTTP {resp.status_code}",
                )
            rows = resp.json() or []

        # First row is a header
        data_rows = rows[1:] if rows and isinstance(rows[0], list) else []
        if not data_rows:
            return WaybackResult(domain=domain)

        # Columns default order: urlkey, timestamp, original, mimetype, statuscode, digest, length
        timestamps = sorted(r[1] for r in data_rows if len(r) > 1)
        recent = [
            f"https://web.archive.org/web/{r[1]}/{r[2]}"
            for r in data_rows[-10:]
            if len(r) > 2
        ]
        return WaybackResult(
            domain=domain,
            first_seen=_format_wayback_ts(timestamps[0]),
            last_seen=_format_wayback_ts(timestamps[-1]),
            snapshot_count=len(data_rows),
            recent_snapshots=recent,
        )
    except Exception as exc:
        logger.warning("Wayback lookup failed for %s: %s", domain, exc)
        return WaybackResult(domain=domain, error=str(exc))
