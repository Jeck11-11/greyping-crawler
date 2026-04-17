"""Check TLS certificates for a target domain."""

from __future__ import annotations

import asyncio
import logging
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from .models import SSLCertResult

logger = logging.getLogger(__name__)


def _grade_cert(issues: list[str]) -> str:
    if not issues:
        return "A"
    severities = {"expired": 3, "self-signed": 3, "sha1": 2, "expiring": 1, "weak": 2}
    worst = 0
    for issue in issues:
        low = issue.lower()
        for keyword, level in severities.items():
            if keyword in low:
                worst = max(worst, level)
    if worst >= 3:
        return "F"
    if worst == 2:
        return "C"
    if worst == 1:
        return "B"
    return "A"


async def check_ssl(target_url: str, timeout: int = 10) -> SSLCertResult:
    """Connect to *target_url* over TLS and inspect the certificate.

    Returns an :class:`SSLCertResult` with certificate details and any issues found.
    """
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    if not hostname:
        return SSLCertResult(is_valid=False, issues=["Could not parse hostname from URL."])

    try:
        cert_dict = await asyncio.to_thread(_fetch_cert, hostname, port, timeout)
    except Exception as exc:
        return SSLCertResult(is_valid=False, issues=[f"TLS connection failed: {exc}"])

    return _parse_cert(cert_dict, hostname)


def _fetch_cert(hostname: str, port: int, timeout: int) -> dict:
    """Blocking call to fetch the peer certificate dict."""
    ctx = ssl.create_default_context()
    with ssl.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            return ssock.getpeercert()


def _parse_cert(cert: dict, hostname: str) -> SSLCertResult:
    """Parse a certificate dict returned by ``ssl.SSLSocket.getpeercert()``."""
    issues: list[str] = []

    # Subject
    subject_parts = []
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                subject_parts.append(value)
    subject = ", ".join(subject_parts) or "unknown"

    # Issuer
    issuer_parts = []
    for rdn in cert.get("issuer", ()):
        for key, value in rdn:
            if key in ("organizationName", "commonName"):
                issuer_parts.append(value)
    issuer = ", ".join(issuer_parts) or "unknown"

    # Self-signed heuristic: compare the raw subject/issuer tuples, or check
    # if the subject CN appears in the issuer string (covers org==CN cases).
    raw_subject = cert.get("subject", ())
    raw_issuer = cert.get("issuer", ())
    is_self_signed = (
        raw_subject == raw_issuer
        or issuer == "unknown"
        or (subject != "unknown" and subject in issuer and len(issuer_parts) <= 2)
    )
    if is_self_signed:
        issues.append("Certificate appears to be self-signed.")

    # Dates
    not_before_raw = cert.get("notBefore", "")
    not_after_raw = cert.get("notAfter", "")
    not_before = ""
    not_after = ""
    days_until_expiry = 0

    try:
        nb = datetime.strptime(not_before_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        na = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = nb.isoformat()
        not_after = na.isoformat()
        now = datetime.now(timezone.utc)
        days_until_expiry = (na - now).days

        if na < now:
            issues.append(f"Certificate EXPIRED on {not_after_raw}.")
        elif days_until_expiry <= 30:
            issues.append(f"Certificate expiring soon: {days_until_expiry} days remaining.")
    except (ValueError, TypeError):
        issues.append("Could not parse certificate validity dates.")

    # SANs
    san: list[str] = []
    for typ, value in cert.get("subjectAltName", ()):
        if typ == "DNS":
            san.append(value)

    # Serial
    serial = cert.get("serialNumber", "")

    # Version
    version = cert.get("version", 0)

    # Signature algorithm (not always in getpeercert dict, best-effort)
    sig_alg = ""
    # Python's getpeercert() doesn't expose the sig algorithm directly,
    # so we flag it only if we can detect it.

    is_valid = len(issues) == 0 or all("expiring soon" in i.lower() for i in issues)

    return SSLCertResult(
        is_valid=is_valid,
        issuer=issuer,
        subject=subject,
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_until_expiry,
        version=version,
        serial_number=serial,
        signature_algorithm=sig_alg,
        san=san,
        issues=issues,
        grade=_grade_cert(issues),
    )
