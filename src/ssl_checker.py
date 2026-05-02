"""Check TLS certificates for a target domain."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from .config import SSL_TIMEOUT
from .models import SSLCertResult

logger = logging.getLogger(__name__)


def _grade_cert(issues: list[str]) -> str:
    if not issues:
        return "A"
    severities = {"expired": 3, "self-signed": 3, "sha1": 2, "expiring": 1, "weak": 2, "deprecated": 2}
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


async def check_ssl(target_url: str, timeout: int = SSL_TIMEOUT) -> SSLCertResult:
    """Connect to *target_url* over TLS and inspect the certificate."""
    parsed = urlparse(target_url)
    hostname = parsed.hostname or ""
    port = parsed.port or 443

    if not hostname:
        return SSLCertResult(cert_valid=False, issues=["Could not parse hostname from URL."])

    try:
        cert_dict, cert_der, tls_version, cipher_name, resolved_ip = await asyncio.to_thread(
            _fetch_cert, hostname, port, timeout,
        )
    except Exception as exc:
        return SSLCertResult(
            cert_valid=False, host=hostname,
            issues=[f"TLS connection failed: {exc}"],
        )

    return _parse_cert(
        cert_dict, hostname,
        cert_der=cert_der,
        tls_version=tls_version,
        cipher=cipher_name,
        resolved_ip=resolved_ip,
    )


def _fetch_cert(
    hostname: str, port: int, timeout: int,
) -> tuple[dict, bytes, str, str, str]:
    """Blocking call to fetch the peer certificate, TLS version, cipher, and resolved IP."""
    ctx = ssl.create_default_context()
    resolved_ip = ""
    try:
        infos = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            resolved_ip = infos[0][4][0]
    except (socket.gaierror, OSError):
        pass

    with ssl.create_connection((hostname, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            cert_der = ssock.getpeercert(binary_form=True) or b""
            tls_version = ssock.version() or ""
            cipher_info = ssock.cipher()
            cipher_name = cipher_info[0] if cipher_info else ""
            if not resolved_ip:
                try:
                    resolved_ip = ssock.getpeername()[0]
                except (OSError, IndexError):
                    pass
            return cert, cert_der, tls_version, cipher_name, resolved_ip


_WEAK_CIPHERS = {"RC4", "DES", "3DES", "RC2", "NULL", "EXPORT", "anon"}

_DEPRECATED_TLS = {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}


def _extract_rdn(cert_tuples: tuple, key: str) -> str:
    """Extract a single value from a certificate subject/issuer tuple."""
    for rdn in cert_tuples:
        for k, v in rdn:
            if k == key:
                return v
    return ""


def _parse_cert(
    cert: dict,
    hostname: str,
    *,
    cert_der: bytes = b"",
    tls_version: str = "",
    cipher: str = "",
    resolved_ip: str = "",
) -> SSLCertResult:
    """Parse a certificate dict returned by ``ssl.SSLSocket.getpeercert()``."""
    issues: list[str] = []

    raw_subject = cert.get("subject", ())
    raw_issuer = cert.get("issuer", ())

    # Subject fields
    issued_to = _extract_rdn(raw_subject, "commonName")
    issued_o = _extract_rdn(raw_subject, "organizationName")
    subject = issued_to or "unknown"

    # Issuer fields
    issuer_cn = _extract_rdn(raw_issuer, "commonName")
    issuer_o = _extract_rdn(raw_issuer, "organizationName")
    issuer_ou = _extract_rdn(raw_issuer, "organizationalUnitName")
    issuer_c = _extract_rdn(raw_issuer, "countryName")

    issuer_parts = [p for p in (issuer_o, issuer_cn) if p]
    issuer = ", ".join(issuer_parts) or "unknown"

    # Self-signed detection
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
    valid_from = ""
    valid_till = ""
    days_left = 0
    validity_days = 0
    is_expired = False

    try:
        nb = datetime.strptime(not_before_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        na = datetime.strptime(not_after_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        valid_from = nb.isoformat()
        valid_till = na.isoformat()
        now = datetime.now(timezone.utc)
        days_left = (na - now).days
        validity_days = (na - nb).days

        if na < now:
            is_expired = True
            issues.append(f"Certificate EXPIRED on {not_after_raw}.")
        elif days_left <= 30:
            issues.append(f"Certificate expiring soon: {days_left} days remaining.")
    except (ValueError, TypeError):
        issues.append("Could not parse certificate validity dates.")

    # SANs
    cert_sans: list[str] = []
    for typ, value in cert.get("subjectAltName", ()):
        if typ == "DNS":
            cert_sans.append(value)

    is_wildcard = any(s.startswith("*.") for s in cert_sans) or (issued_to and issued_to.startswith("*."))

    # Serial
    cert_sn = cert.get("serialNumber", "")

    # Version
    cert_ver = cert.get("version", 0)

    # SHA-1 fingerprint
    cert_sha1 = ""
    if cert_der:
        cert_sha1 = hashlib.sha1(cert_der).hexdigest().upper()
        cert_sha1 = ":".join(cert_sha1[i:i+2] for i in range(0, len(cert_sha1), 2))

    # Signature algorithm (from DER via cryptography lib, optional)
    cert_alg = ""
    if cert_der:
        try:
            from cryptography import x509
            parsed_cert = x509.load_der_x509_certificate(cert_der)
            cert_alg = parsed_cert.signature_algorithm_oid._name
        except BaseException:
            pass

    # TLS version check
    if tls_version and tls_version in _DEPRECATED_TLS:
        issues.append(f"Deprecated TLS version: {tls_version}.")

    # Cipher strength check
    if cipher:
        cipher_upper = cipher.upper()
        for weak in _WEAK_CIPHERS:
            if weak.upper() in cipher_upper:
                issues.append(f"Weak cipher detected: {cipher}.")
                break

    cert_valid = len(issues) == 0 or all("expiring soon" in i.lower() for i in issues)

    return SSLCertResult(
        cert_valid=cert_valid,
        valid_from=valid_from,
        valid_till=valid_till,
        days_left=days_left,
        valid_days_to_expire=days_left,
        cert_ver=cert_ver,
        cert_sn=cert_sn,
        cert_alg=cert_alg,
        cert_sans=cert_sans,
        issues=issues,
        grade=_grade_cert(issues),
        tls_version=tls_version,
        cipher=cipher,
        host=hostname,
        resolved_ip=resolved_ip,
        issued_to=issued_to,
        issued_o=issued_o,
        issuer_c=issuer_c,
        issuer_o=issuer_o,
        issuer_ou=issuer_ou,
        issuer_cn=issuer_cn,
        cert_sha1=cert_sha1,
        cert_exp=is_expired,
        validity_days=validity_days,
        is_self_signed=is_self_signed,
        is_wildcard=is_wildcard,
    )
