"""Analyze HTTP response headers for security best practices."""

from __future__ import annotations

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
]

# Headers whose presence leaks information
_LEAK_HEADERS: list[tuple[str, str]] = [
    ("Server", "Remove or obfuscate the Server header to avoid disclosing software versions."),
    ("X-Powered-By", "Remove the X-Powered-By header to avoid disclosing framework details."),
]


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
            # Check for weak values
            status = "present"
            if header == "Strict-Transport-Security" and "max-age=0" in value:
                status = "weak"
                recommendation = "HSTS max-age is 0, which effectively disables HSTS."
                score -= severity_penalty.get(severity, 5)
            elif header == "X-Frame-Options" and value.upper() == "ALLOWALL":
                status = "weak"
                recommendation = "X-Frame-Options: ALLOWALL does not prevent click-jacking."
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

    score = max(0, score)

    return SecurityHeadersResult(
        grade=_score_to_grade(score),
        score=score,
        findings=findings,
        server=server_value,
        powered_by=powered_by,
    )
