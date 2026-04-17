"""Tests for the cookie security auditor."""

from http.cookiejar import Cookie
from unittest.mock import MagicMock

from src.cookie_checker import analyze_cookies


def _make_cookie(
    name: str = "session",
    secure: bool = False,
    httponly: bool = False,
    samesite: str = "",
    path: str = "/",
) -> Cookie:
    """Build a minimal Cookie object for testing."""
    rest: dict = {}
    if httponly:
        rest["httpOnly"] = ""
    if samesite:
        rest["sameSite"] = samesite
    return Cookie(
        version=0, name=name, value="abc123",
        port=None, port_specified=False,
        domain=".example.com", domain_specified=True, domain_initial_dot=True,
        path=path, path_specified=True,
        secure=secure,
        expires=None, discard=True,
        comment=None, comment_url=None,
        rest=rest,
    )


class TestAnalyzeCookies:
    def test_secure_cookie_no_issues(self):
        cookie = _make_cookie(secure=True, httponly=True, samesite="Strict")
        findings = analyze_cookies([cookie])
        assert len(findings) == 1
        assert findings[0].issues == []

    def test_missing_secure_flag(self):
        cookie = _make_cookie(secure=False, httponly=True, samesite="Lax")
        findings = analyze_cookies([cookie])
        assert any("Secure" in i for i in findings[0].issues)

    def test_missing_httponly_flag(self):
        cookie = _make_cookie(secure=True, httponly=False, samesite="Lax")
        findings = analyze_cookies([cookie])
        assert any("HttpOnly" in i for i in findings[0].issues)

    def test_missing_samesite(self):
        cookie = _make_cookie(secure=True, httponly=True, samesite="")
        findings = analyze_cookies([cookie])
        assert any("SameSite" in i for i in findings[0].issues)

    def test_samesite_none_without_secure(self):
        cookie = _make_cookie(secure=False, httponly=True, samesite="None")
        findings = analyze_cookies([cookie])
        assert findings[0].severity == "high"
        assert any("SameSite=None" in i for i in findings[0].issues)

    def test_session_cookie_higher_severity(self):
        cookie = _make_cookie(name="auth_token", secure=False, httponly=False)
        findings = analyze_cookies([cookie])
        assert findings[0].severity == "high"

    def test_empty_list_returns_empty(self):
        findings = analyze_cookies([])
        assert findings == []
