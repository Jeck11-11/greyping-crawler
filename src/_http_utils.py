"""Shared HTTP helpers used by both the orchestrator and the per-capability routers."""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from urllib.parse import urlparse

import httpx

from .config import HTTP_TIMEOUT, MAX_RESPONSE_BYTES, UA_BROWSER, UA_HONEST

logger = logging.getLogger(__name__)


class TargetValidationError(ValueError):
    """Raised when a target URL fails security validation."""


_BLOCKED_SCHEMES = frozenset({"file", "ftp", "data", "javascript", "gopher"})

_DENYLIST_HOSTS: frozenset[str] = frozenset(
    h.strip().lower()
    for h in os.getenv("TARGET_DENYLIST", "").split(",")
    if h.strip()
)


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return False


def validate_target(raw: str) -> str:
    """Normalise *raw* and validate it against SSRF / private-IP rules.

    Returns the normalised URL on success; raises
    :class:`TargetValidationError` on any violation.
    """
    raw = raw.strip()
    if not raw:
        raise TargetValidationError("Empty target")

    pre_parsed = urlparse(raw)
    if pre_parsed.scheme and pre_parsed.scheme in _BLOCKED_SCHEMES:
        raise TargetValidationError(f"Blocked scheme: {pre_parsed.scheme}")

    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"

    parsed = urlparse(raw)

    if parsed.scheme not in ("http", "https"):
        raise TargetValidationError(f"Blocked scheme: {parsed.scheme}")

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise TargetValidationError("No hostname in target URL")

    if hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise TargetValidationError(f"Loopback target blocked: {hostname}")

    if _is_private_ip(hostname):
        raise TargetValidationError(f"Private/reserved IP blocked: {hostname}")

    if hostname in _DENYLIST_HOSTS:
        raise TargetValidationError(f"Denylisted host: {hostname}")

    try:
        resolved = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _family, _type, _proto, _canonname, sockaddr in resolved:
            ip = sockaddr[0]
            if _is_private_ip(ip):
                raise TargetValidationError(
                    f"Host {hostname} resolves to private IP {ip}"
                )
    except socket.gaierror:
        pass
    except TargetValidationError:
        raise
    except Exception:
        pass

    return raw


async def fetch_landing_page(
    target: str,
    *,
    timeout: int = HTTP_TIMEOUT,
) -> tuple[dict[str, str], httpx.Cookies]:
    """GET the landing page and return (response_headers, cookies).

    Returns empty results on any failure — the caller decides how to grade
    a target that was unreachable.
    """
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(timeout),
            verify=False,
        ) as client:
            resp = await client.get(
                target,
                headers={"User-Agent": UA_HONEST},
            )
            return dict(resp.headers), resp.cookies
    except Exception as exc:
        logger.warning("Landing page fetch failed for %s: %s", target, exc)
        return {}, httpx.Cookies()


_STEALTH_HEADERS = {
    "User-Agent": UA_BROWSER,
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}


async def fetch_landing_page_full(
    target: str,
    *,
    timeout: int = HTTP_TIMEOUT,
    stealth: bool = False,
) -> tuple[dict[str, str], httpx.Cookies, str]:
    """Like :func:`fetch_landing_page`, but also returns the response body (HTML).

    Used by tech-fingerprinting and JS-intel endpoints that need the HTML.

    When *stealth* is ``True``, swap the honest ``GreypingCrawler/1.0``
    identifier for a realistic Chrome User-Agent plus the modern
    ``Sec-Fetch-*`` headers a real browser sends. This is what the
    light-touch orchestrator uses so a single GET looks like a real
    visitor to a WAF.
    """
    headers = dict(_STEALTH_HEADERS) if stealth else {"User-Agent": UA_HONEST}
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=httpx.Timeout(timeout),
            verify=False,
        ) as client:
            resp = await client.get(target, headers=headers)
            body = resp.text[:MAX_RESPONSE_BYTES] if len(resp.content) > MAX_RESPONSE_BYTES else resp.text
            return dict(resp.headers), resp.cookies, body
    except Exception as exc:
        logger.warning("Landing page fetch (full) failed for %s: %s", target, exc)
        return {}, httpx.Cookies(), ""


def normalise_target(raw: str) -> str:
    """Ensure the target has a scheme so urlparse works correctly."""
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = f"https://{raw}"
    return raw
