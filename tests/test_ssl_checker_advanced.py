"""Advanced SSL checker tests for TLS version and cipher detection."""

from datetime import datetime, timedelta, timezone

from src.ssl_checker import _parse_cert


def _make_cert(*, days_valid=365, issuer_cn="Let's Encrypt", subject_cn="example.com"):
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
        "subjectAltName": (("DNS", "example.com"),),
    }


class TestTLSVersionDetection:
    def test_tls13_no_issues(self):
        cert = _make_cert()
        result = _parse_cert(cert, "example.com", tls_version="TLSv1.3")
        assert result.tls_version == "TLSv1.3"
        assert not any("deprecated" in i.lower() for i in result.issues)

    def test_tls12_no_issues(self):
        cert = _make_cert()
        result = _parse_cert(cert, "example.com", tls_version="TLSv1.2")
        assert result.tls_version == "TLSv1.2"
        assert not any("deprecated" in i.lower() for i in result.issues)

    def test_tls11_flagged_deprecated(self):
        cert = _make_cert()
        result = _parse_cert(cert, "example.com", tls_version="TLSv1.1")
        assert any("Deprecated TLS" in i for i in result.issues)
        assert not result.cert_valid

    def test_tls10_flagged_deprecated(self):
        cert = _make_cert()
        result = _parse_cert(cert, "example.com", tls_version="TLSv1")
        assert any("Deprecated TLS" in i for i in result.issues)

    def test_sslv3_flagged_deprecated(self):
        cert = _make_cert()
        result = _parse_cert(cert, "example.com", tls_version="SSLv3")
        assert any("Deprecated TLS" in i for i in result.issues)


class TestCipherDetection:
    def test_strong_cipher_no_issues(self):
        cert = _make_cert()
        result = _parse_cert(
            cert, "example.com",
            tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384",
        )
        assert result.cipher == "TLS_AES_256_GCM_SHA384"
        assert not any("weak cipher" in i.lower() for i in result.issues)

    def test_rc4_cipher_flagged(self):
        cert = _make_cert()
        result = _parse_cert(
            cert, "example.com",
            tls_version="TLSv1.2", cipher="RC4-SHA",
        )
        assert any("Weak cipher" in i for i in result.issues)

    def test_des_cipher_flagged(self):
        cert = _make_cert()
        result = _parse_cert(
            cert, "example.com",
            tls_version="TLSv1.2", cipher="DES-CBC3-SHA",
        )
        assert any("Weak cipher" in i for i in result.issues)

    def test_null_cipher_flagged(self):
        cert = _make_cert()
        result = _parse_cert(
            cert, "example.com",
            tls_version="TLSv1.2", cipher="NULL-SHA256",
        )
        assert any("Weak cipher" in i for i in result.issues)


class TestGradeWithTLS:
    def test_deprecated_tls_gets_grade_c(self):
        cert = _make_cert()
        result = _parse_cert(cert, "example.com", tls_version="TLSv1.1")
        assert result.grade in ("C", "F")

    def test_weak_cipher_gets_grade_c(self):
        cert = _make_cert()
        result = _parse_cert(
            cert, "example.com",
            tls_version="TLSv1.2", cipher="RC4-SHA",
        )
        assert result.grade in ("C", "F")
