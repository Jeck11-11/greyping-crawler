"""Audit cookies returned by a target for security best practices."""

from __future__ import annotations

from http.cookiejar import Cookie
from typing import Sequence

import httpx

from .models import CookieFinding


def analyze_cookies(
    cookies: httpx.Cookies | Sequence[Cookie] | None = None,
    *,
    browser_cookies: list[dict] | None = None,
) -> list[CookieFinding]:
    """Inspect *cookies* for missing Secure, HttpOnly, and SameSite flags.

    Accepts an ``httpx.Cookies`` jar, a list of ``Cookie`` objects, or
    Playwright browser cookie dicts (from ``context.cookies()``).
    When both *cookies* and *browser_cookies* are provided the results
    are merged (deduplicated by name).
    """
    findings: list[CookieFinding] = []
    seen_names: set[str] = set()

    if cookies is not None:
        for cookie in cookies.jar if isinstance(cookies, httpx.Cookies) else cookies:
            seen_names.add(cookie.name)
            findings.append(_assess_http_cookie(cookie))

    for bc in browser_cookies or []:
        name = bc.get("name", "")
        if name in seen_names:
            continue
        seen_names.add(name)
        findings.append(_assess_browser_cookie(bc))

    return findings


def _assess_http_cookie(cookie: Cookie) -> CookieFinding:
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

    name_lower = cookie.name.lower()
    if any(tok in name_lower for tok in ("session", "auth", "token", "jwt", "sid")) and issues:
        severity = "high"

    return CookieFinding(
        name=cookie.name,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        path=path,
        issues=issues,
        severity=severity,
    )


def _assess_browser_cookie(bc: dict) -> CookieFinding:
    """Assess a Playwright cookie dict."""
    name = bc.get("name", "")
    secure = bc.get("secure", False)
    http_only = bc.get("httpOnly", False)
    same_site = bc.get("sameSite", "")
    path = bc.get("path", "/")

    issues: list[str] = []
    severity = "low"

    if not secure:
        issues.append("Missing Secure flag – cookie may be sent over HTTP.")
        severity = "medium"
    if not http_only:
        issues.append("Missing HttpOnly flag – cookie is accessible to JavaScript (XSS risk).")
        severity = "medium"
    if not same_site or same_site == "None":
        if same_site == "None" and not secure:
            issues.append("SameSite=None requires the Secure flag; browsers may reject this cookie.")
            severity = "high"
        elif not same_site:
            issues.append("Missing SameSite attribute – vulnerable to CSRF in older browsers.")

    name_lower = name.lower()
    if any(tok in name_lower for tok in ("session", "auth", "token", "jwt", "sid")) and issues:
        severity = "high"

    return CookieFinding(
        name=name,
        secure=secure,
        http_only=http_only,
        same_site=same_site,
        path=path,
        issues=issues,
        severity=severity,
    )


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
