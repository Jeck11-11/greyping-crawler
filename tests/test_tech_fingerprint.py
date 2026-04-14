"""Tests for the Wappalyzer-style technology fingerprinter."""

from src.tech_fingerprint import fingerprint_tech


def test_wordpress_via_meta_and_html():
    html = """
    <html><head><meta name="generator" content="WordPress 6.4.1"></head>
    <body><link href="/wp-content/themes/foo.css"></body></html>
    """
    findings = fingerprint_tech(
        html=html,
        headers={},
        script_urls=[],
        meta={"generator": "WordPress 6.4.1"},
    )
    names = {f.name for f in findings}
    assert "WordPress" in names
    wp = next(f for f in findings if f.name == "WordPress")
    assert wp.version == "6.4.1"
    assert wp.confidence in {"medium", "high"}


def test_nginx_via_server_header():
    findings = fingerprint_tech(
        html="",
        headers={"server": "nginx/1.18.0"},
        script_urls=[],
        meta={},
    )
    nginx = next(f for f in findings if f.name == "Nginx")
    assert nginx.version == "1.18.0"
    assert "header:server" in nginx.evidence


def test_jquery_via_script_url_extracts_version():
    findings = fingerprint_tech(
        html="",
        headers={},
        script_urls=["https://cdn.example.com/jquery-3.7.1.min.js"],
        meta={},
    )
    jq = next(f for f in findings if f.name == "jQuery")
    assert jq.version == "3.7.1"


def test_cloudflare_via_header_and_cookie_names():
    class _Cookie:
        def __init__(self, name):
            self.name = name

    findings = fingerprint_tech(
        html="",
        headers={"cf-ray": "abc123-LHR"},
        cookies=[_Cookie("__cf_bm")],
        script_urls=[],
        meta={},
    )
    cf = next(f for f in findings if f.name == "Cloudflare")
    assert "header:cf-ray" in cf.evidence
    assert "cookie" in cf.evidence
    # Two signals => medium confidence
    assert cf.confidence == "medium"


def test_no_signals_returns_empty():
    findings = fingerprint_tech(
        html="<html><body>hello</body></html>",
        headers={},
        script_urls=[],
        meta={},
    )
    assert findings == []
