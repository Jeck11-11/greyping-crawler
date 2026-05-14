"""Analyze HTTP response headers for security best practices."""

from __future__ import annotations

import re

from .models import HeaderFinding, SecurityHeadersResult


# Each entry: (header_name, severity_if_missing, recommendation)
_REQUIRED_HEADERS: list[tuple[str, str, str]] = [
    (
        "Strict-Transport-Security",
        "high",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
    ),
    (
        "Content-Security-Policy",
        "high",
        "Add a Content-Security-Policy header to prevent XSS and data-injection attacks.",
    ),
    (
        "X-Frame-Options",
        "medium",
        "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent click-jacking.",
    ),
    (
        "X-Content-Type-Options",
        "medium",
        "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type sniffing.",
    ),
    (
        "Referrer-Policy",
        "low",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin' to limit referrer leakage.",
    ),
    (
        "Permissions-Policy",
        "low",
        "Add a Permissions-Policy header to restrict browser features (camera, mic, geolocation).",
    ),
    (
        "Cross-Origin-Opener-Policy",
        "low",
        "Add 'Cross-Origin-Opener-Policy: same-origin' to isolate browsing context from cross-origin popups.",
    ),
    (
        "Cross-Origin-Resource-Policy",
        "low",
        "Add 'Cross-Origin-Resource-Policy: same-origin' to prevent cross-origin reads of resources.",
    ),
    (
        "X-Permitted-Cross-Domain-Policies",
        "low",
        "Add 'X-Permitted-Cross-Domain-Policies: none' to prevent Adobe Flash/Acrobat cross-domain data loading.",
    ),
]

# Headers whose presence leaks information
_LEAK_HEADERS: list[tuple[str, str]] = [
    ("Server", "Remove or obfuscate the Server header to avoid disclosing software versions."),
    ("X-Powered-By", "Remove the X-Powered-By header to avoid disclosing framework details."),
]

_HSTS_MIN_MAX_AGE = 31536000  # 1 year in seconds

_CSP_UNSAFE_DIRECTIVES = re.compile(
    r"'unsafe-inline'|'unsafe-eval'", re.IGNORECASE,
)

_CSP_WILDCARD_SRC = re.compile(
    r"(?:default-src|script-src|style-src|img-src|connect-src|object-src)\s+[^;]*(?<!')\*(?!')",
    re.IGNORECASE,
)


def _check_hsts(value: str) -> tuple[str, str]:
    """Return (status, recommendation) for an HSTS header value."""
    if "max-age=0" in value:
        return "weak", "HSTS max-age is 0, which effectively disables HSTS."
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    if match:
        age = int(match.group(1))
        if age < _HSTS_MIN_MAX_AGE:
            return "weak", (
                f"HSTS max-age is {age}s ({age // 86400}d) — "
                f"recommended minimum is {_HSTS_MIN_MAX_AGE}s (1 year). "
                "Add includeSubDomains for full coverage."
            )
    return "present", ""


def _check_csp(value: str) -> tuple[str, str]:
    """Return (status, recommendation) for a CSP header value."""
    issues: list[str] = []
    if _CSP_UNSAFE_DIRECTIVES.search(value):
        issues.append("'unsafe-inline' or 'unsafe-eval' weakens XSS protection")
    if _CSP_WILDCARD_SRC.search(value):
        issues.append("wildcard (*) source allows loading from any origin")
    if issues:
        return "weak", f"CSP is present but weak: {'; '.join(issues)}. Tighten directive sources."
    return "present", ""


def _score_to_grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def analyze_headers(headers: dict[str, str]) -> SecurityHeadersResult:
    """Score and grade the security headers from an HTTP response.

    *headers* should be a case-insensitive dict (e.g. ``httpx.Headers``).
    """
    # Normalise header names to lower-case for reliable lookup
    lower: dict[str, str] = {k.lower(): v for k, v in headers.items()}
    findings: list[HeaderFinding] = []

    # Scoring: start at 100, deduct for missing / weak headers
    score = 100
    severity_penalty = {"critical": 20, "high": 15, "medium": 10, "low": 5}

    for header, severity, recommendation in _REQUIRED_HEADERS:
        value = lower.get(header.lower(), "")
        if value:
            status = "present"
            rec = ""
            if header == "Strict-Transport-Security":
                status, rec = _check_hsts(value)
            elif header == "Content-Security-Policy":
                status, rec = _check_csp(value)
            elif header == "X-Frame-Options" and value.upper() == "ALLOWALL":
                status = "weak"
                rec = "X-Frame-Options: ALLOWALL does not prevent click-jacking."
            if status == "weak":
                recommendation = rec
                score -= severity_penalty.get(severity, 5)
        else:
            status = "missing"
            score -= severity_penalty.get(severity, 5)

        findings.append(
            HeaderFinding(
                header=header,
                status=status,
                value=value,
                recommendation=recommendation if status != "present" else "",
                severity=severity if status != "present" else "info",
            )
        )

    # Information-leakage headers
    server_value = lower.get("server", "")
    powered_by = lower.get("x-powered-by", "")

    for header, recommendation in _LEAK_HEADERS:
        value = lower.get(header.lower(), "")
        if value:
            findings.append(
                HeaderFinding(
                    header=header,
                    status="present",
                    value=value,
                    recommendation=recommendation,
                    severity="low",
                )
            )
            score -= 3  # small penalty for information leakage

    # CORS misconfiguration detection
    cors_origin = lower.get("access-control-allow-origin", "")
    cors_credentials = lower.get("access-control-allow-credentials", "").lower()
    if cors_origin == "*":
        findings.append(
            HeaderFinding(
                header="Access-Control-Allow-Origin",
                status="misconfigured",
                value=cors_origin,
                recommendation="Wildcard CORS allows any website to read responses. Restrict to trusted origins.",
                severity="high",
            )
        )
        score -= 15
    elif cors_origin and cors_credentials == "true":
        findings.append(
            HeaderFinding(
                header="Access-Control-Allow-Origin",
                status="misconfigured",
                value=f"{cors_origin} (with credentials)",
                recommendation="CORS with credentials allows the specified origin to make authenticated requests. Verify this origin is trusted.",
                severity="medium",
            )
        )
        score -= 10

    # Cache-Control on sensitive pages
    cache_control = lower.get("cache-control", "")
    if not cache_control or ("no-store" not in cache_control.lower() and "private" not in cache_control.lower()):
        findings.append(
            HeaderFinding(
                header="Cache-Control",
                status="missing" if not cache_control else "weak",
                value=cache_control,
                recommendation="Add 'Cache-Control: no-store' or 'private' to prevent caching of sensitive responses.",
                severity="low",
            )
        )
        score -= 3

    score = max(0, score)

    return SecurityHeadersResult(
        grade=_score_to_grade(score),
        score=score,
        findings=findings,
        server=server_value,
        powered_by=powered_by,
    )
