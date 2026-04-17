"""Audit cookies returned by a target for security best practices."""

from __future__ import annotations

from http.cookiejar import Cookie
from typing import Sequence

import httpx

from .models import CookieFinding


def analyze_cookies(cookies: httpx.Cookies | Sequence[Cookie]) -> list[CookieFinding]:
    """Inspect *cookies* for missing Secure, HttpOnly, and SameSite flags.

    Accepts either an ``httpx.Cookies`` jar or a list of ``Cookie`` objects.
    """
    findings: list[CookieFinding] = []

    for cookie in cookies.jar if isinstance(cookies, httpx.Cookies) else cookies:
        issues: list[str] = []
        severity = "low"

        secure = getattr(cookie, "secure", False)
        http_only = _has_httponly(cookie)
        same_site = _get_samesite(cookie)
        path = getattr(cookie, "path", "/")

        if not secure:
            issues.append("Missing Secure flag – cookie may be sent over HTTP.")
            severity = "medium"
        if not http_only:
            issues.append("Missing HttpOnly flag – cookie is accessible to JavaScript (XSS risk).")
            severity = "medium"
        if not same_site:
            issues.append("Missing SameSite attribute – vulnerable to CSRF in older browsers.")
        elif same_site.lower() == "none" and not secure:
            issues.append("SameSite=None requires the Secure flag; browsers may reject this cookie.")
            severity = "high"

        # Session-looking cookies get a higher severity bump
        name_lower = cookie.name.lower()
        if any(tok in name_lower for tok in ("session", "auth", "token", "jwt", "sid")) and issues:
            severity = "high"

        findings.append(
            CookieFinding(
                name=cookie.name,
                secure=secure,
                http_only=http_only,
                same_site=same_site,
                path=path,
                issues=issues,
                severity=severity,
            )
        )

    return findings


def _has_httponly(cookie: Cookie) -> bool:
    """Check if the cookie has the HttpOnly flag set."""
    # http.cookiejar stores extra attributes in _rest
    rest: dict = getattr(cookie, "_rest", {})
    for key in rest:
        if key.lower() == "httponly":
            return True
    return False


def _get_samesite(cookie: Cookie) -> str:
    """Return the SameSite attribute value, or empty string if absent."""
    rest: dict = getattr(cookie, "_rest", {})
    for key, value in rest.items():
        if key.lower() == "samesite":
            return value if value else key  # Some jars store it oddly
    return ""
