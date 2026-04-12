"""Tests for the SSL certificate checker."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from src.ssl_checker import _parse_cert, check_ssl


class TestParseCert:
    def _make_cert(self, *, days_valid=365, issuer_cn="Let's Encrypt", subject_cn="example.com"):
        now = datetime.now(timezone.utc)
        nb = now - timedelta(days=30)
        na = now + timedelta(days=days_valid)
        return {
            "subject": ((("commonName", subject_cn),),),
            "issuer": (
                (("organizationName", issuer_cn),),
                (("commonName", issuer_cn),),
            ),
            "notBefore": nb.strftime("%b %d %H:%M:%S %Y GMT"),
            "notAfter": na.strftime("%b %d %H:%M:%S %Y GMT"),
            "serialNumber": "ABC123",
            "version": 3,
            "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
        }

    def test_valid_cert_gets_grade_a(self):
        cert = self._make_cert()
        result = _parse_cert(cert, "example.com")
        assert result.is_valid
        assert result.grade == "A"
        assert result.issuer == "Let's Encrypt, Let's Encrypt"
        assert result.subject == "example.com"
        assert len(result.san) == 2

    def test_expired_cert_flagged(self):
        cert = self._make_cert(days_valid=-10)
        result = _parse_cert(cert, "example.com")
        assert not result.is_valid
        assert result.grade == "F"
        assert any("EXPIRED" in i for i in result.issues)

    def test_expiring_soon_flagged(self):
        cert = self._make_cert(days_valid=15)
        result = _parse_cert(cert, "example.com")
        assert result.grade == "B"
        assert any("expiring soon" in i.lower() for i in result.issues)

    def test_self_signed_flagged(self):
        cert = self._make_cert(issuer_cn="example.com", subject_cn="example.com")
        result = _parse_cert(cert, "example.com")
        assert any("self-signed" in i.lower() for i in result.issues)
        assert result.grade == "F"


class TestCheckSSL:
    @pytest.mark.asyncio
    async def test_bad_hostname_returns_error(self):
        result = await check_ssl("https://this-does-not-exist-8374.test", timeout=3)
        assert not result.is_valid
        assert len(result.issues) > 0

    @pytest.mark.asyncio
    async def test_empty_url_returns_error(self):
        result = await check_ssl("", timeout=3)
        assert not result.is_valid
        assert any("hostname" in i.lower() for i in result.issues)
