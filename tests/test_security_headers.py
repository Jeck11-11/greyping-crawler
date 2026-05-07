"""Tests for the security headers analyzer."""

from src.security_headers import analyze_headers


class TestAnalyzeHeaders:
    def test_all_headers_present_gets_high_score(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-Permitted-Cross-Domain-Policies": "none",
        }
        result = analyze_headers(headers)
        assert result.grade == "A"
        assert result.score >= 90
        assert all(f.status == "present" for f in result.findings)

    def test_no_headers_gets_f(self):
        result = analyze_headers({})
        assert result.grade in ("D", "F")
        assert result.score < 50
        missing = [f for f in result.findings if f.status == "missing"]
        assert len(missing) >= 4

    def test_detects_server_leak(self):
        headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
        result = analyze_headers(headers)
        assert result.server == "Apache/2.4.41 (Ubuntu)"
        assert any(f.header == "Server" and f.status == "present" for f in result.findings)

    def test_detects_powered_by_leak(self):
        headers = {"X-Powered-By": "PHP/7.4.3"}
        result = analyze_headers(headers)
        assert result.powered_by == "PHP/7.4.3"

    def test_weak_hsts_flagged(self):
        headers = {"Strict-Transport-Security": "max-age=0"}
        result = analyze_headers(headers)
        hsts = [f for f in result.findings if f.header == "Strict-Transport-Security"]
        assert len(hsts) == 1
        assert hsts[0].status == "weak"

    def test_case_insensitive_lookup(self):
        headers = {"strict-transport-security": "max-age=31536000"}
        result = analyze_headers(headers)
        hsts = [f for f in result.findings if f.header == "Strict-Transport-Security"]
        assert len(hsts) == 1
        assert hsts[0].status == "present"

    def test_cors_wildcard_detected(self):
        headers = {"Access-Control-Allow-Origin": "*"}
        result = analyze_headers(headers)
        cors = [f for f in result.findings if f.header == "Access-Control-Allow-Origin"]
        assert len(cors) == 1
        assert cors[0].status == "misconfigured"
        assert cors[0].severity == "high"

    def test_cors_credentials_detected(self):
        headers = {
            "Access-Control-Allow-Origin": "https://evil.com",
            "Access-Control-Allow-Credentials": "true",
        }
        result = analyze_headers(headers)
        cors = [f for f in result.findings if f.header == "Access-Control-Allow-Origin"]
        assert len(cors) == 1
        assert cors[0].severity == "medium"
