"""C99.nl API client for subdomain discovery, IP/URL reputation, and email validation."""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

C99_API_KEY = os.getenv("C99_API_KEY", "")
C99_BASE_URL = "https://api.c99.nl"
C99_TIMEOUT = int(os.getenv("C99_TIMEOUT", "20"))


async def _c99_get(endpoint: str, params: dict[str, str], timeout: int = C99_TIMEOUT) -> dict | None:
    if not C99_API_KEY:
        print(f"[C99] {endpoint} skipped — no API key", flush=True)
        return None
    params["key"] = C99_API_KEY
    params["json"] = ""
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.get(f"{C99_BASE_URL}/{endpoint}", params=params)
            resp.raise_for_status()
            data = resp.json()
            print(f"[C99] {endpoint} response (status={resp.status_code}): {str(data)[:500]}", flush=True)
            return data
    except Exception as exc:
        print(f"[C99] {endpoint} failed: {exc}", flush=True)
        logger.warning("C99 %s failed: %s", endpoint, exc)
        return None


async def find_subdomains(domain: str, *, timeout: int = C99_TIMEOUT) -> list[str]:
    """Discover subdomains via C99's subdomain finder."""
    data = await _c99_get("subdomainfinder", {"domain": domain}, timeout=timeout)
    if not data or not data.get("success"):
        return []
    subs = data.get("subdomains") or []
    result: list[str] = []
    for entry in subs:
        if isinstance(entry, dict):
            sub = entry.get("subdomain", "")
        else:
            sub = str(entry)
        sub = sub.strip().lower().rstrip(".")
        if sub:
            result.append(sub)
    return result


async def check_ip_reputation(ip: str, *, timeout: int = C99_TIMEOUT) -> dict[str, Any]:
    """Check if an IP is involved in malicious activity."""
    data = await _c99_get("ipreputation", {"host": ip}, timeout=timeout)
    if not data or not data.get("success"):
        return {"ip": ip, "malicious": False, "error": "lookup failed"}
    rep = data.get("result") or data
    return {
        "ip": ip,
        "malicious": rep.get("malicious", False),
        "details": rep.get("details") or rep.get("result") or {},
        "raw": rep,
    }


async def check_url_reputation(url: str, *, timeout: int = C99_TIMEOUT) -> dict[str, Any]:
    """Check a URL against multiple blacklists."""
    data = await _c99_get("reputationchecker", {"url": url}, timeout=timeout)
    if not data or not data.get("success"):
        return {"url": url, "blacklisted": False, "error": "lookup failed"}
    result = data.get("result") or data
    blacklisted = False
    detections: list[str] = []
    if isinstance(result, dict):
        for source, status in result.items():
            if source in ("success",):
                continue
            if isinstance(status, str) and any(w in status.lower() for w in ("blacklisted", "malicious", "unsafe", "phishing", "malware")):
                blacklisted = True
                detections.append(f"{source}: {status}")
            elif isinstance(status, dict) and status.get("detected"):
                blacklisted = True
                detections.append(source)
    return {
        "url": url,
        "blacklisted": blacklisted,
        "detections": detections,
        "sources_checked": len(result) if isinstance(result, dict) else 0,
        "raw": result,
    }


async def validate_email(email: str, *, timeout: int = C99_TIMEOUT) -> dict[str, Any]:
    """Validate whether an email address is deliverable."""
    data = await _c99_get("emailvalidator", {"email": email}, timeout=timeout)
    if not data:
        return {"email": email, "valid": None, "error": "C99 API unavailable"}
    if not data.get("success"):
        return {"email": email, "valid": None, "error": data.get("error", "lookup failed")}
    result = data.get("result") or data
    if isinstance(result, str):
        is_valid = result.lower() in ("valid", "true", "ok", "deliverable")
        return {"email": email, "valid": is_valid}
    if isinstance(result, bool):
        return {"email": email, "valid": result}
    if isinstance(result, dict):
        valid_val = result.get("valid", result.get("is_valid", result.get("deliverable")))
        if isinstance(valid_val, str):
            valid_val = valid_val.lower() in ("true", "valid", "ok", "deliverable", "1")
        return {
            "email": email,
            "valid": valid_val,
            "disposable": result.get("disposable", False),
            "role_account": result.get("role", result.get("role_account", False)),
            "free_provider": result.get("free", result.get("free_provider", False)),
            "details": result,
        }
    return {"email": email, "valid": None, "details": result}
