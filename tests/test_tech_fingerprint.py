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


def test_xsrf_token_cookie_alone_does_not_flag_laravel():
    """XSRF-TOKEN is a generic CSRF cookie (Angular, Axios, Wix, Spring)
    and should NOT trigger a Laravel detection by itself."""

    class _Cookie:
        def __init__(self, name):
            self.name = name

    findings = fingerprint_tech(
        html="",
        headers={},
        cookies=[_Cookie("XSRF-TOKEN")],
        script_urls=[],
        meta={},
    )
    names = {f.name for f in findings}
    assert "Laravel" not in names


def test_laravel_detected_via_laravel_session_cookie():
    """The laravel_session cookie IS Laravel-specific."""

    class _Cookie:
        def __init__(self, name):
            self.name = name

    findings = fingerprint_tech(
        html="",
        headers={},
        cookies=[_Cookie("laravel_session")],
        script_urls=[],
        meta={},
    )
    names = {f.name for f in findings}
    assert "Laravel" in names


def test_laravel_cookie_match_is_anchored():
    """A cookie named 'my_laravel_session_extra' should not trigger Laravel."""

    class _Cookie:
        def __init__(self, name):
            self.name = name

    findings = fingerprint_tech(
        html="",
        headers={},
        cookies=[_Cookie("my_laravel_session_extra")],
        script_urls=[],
        meta={},
    )
    names = {f.name for f in findings}
    assert "Laravel" not in names


def test_sessionid_cookie_alone_does_not_flag_django():
    """'sessionid' is used by Flask, generic Python, and many other
    frameworks — it should NOT be enough to fingerprint Django."""

    class _Cookie:
        def __init__(self, name):
            self.name = name

    findings = fingerprint_tech(
        html="", headers={},
        cookies=[_Cookie("sessionid")],
        script_urls=[], meta={},
    )
    names = {f.name for f in findings}
    assert "Django" not in names


def test_django_detected_via_csrftoken_cookie():
    class _Cookie:
        def __init__(self, name):
            self.name = name

    findings = fingerprint_tech(
        html="", headers={},
        cookies=[_Cookie("csrftoken")],
        script_urls=[], meta={},
    )
    names = {f.name for f in findings}
    assert "Django" in names


def test_session_id_cookie_alone_does_not_flag_rails():
    """'_session_id' is generic — many frameworks use it."""

    class _Cookie:
        def __init__(self, name):
            self.name = name

    findings = fingerprint_tech(
        html="", headers={},
        cookies=[_Cookie("_session_id")],
        script_urls=[], meta={},
    )
    names = {f.name for f in findings}
    assert "Ruby on Rails" not in names


def test_rails_detected_via_rails_session_cookie():
    class _Cookie:
        def __init__(self, name):
            self.name = name

    findings = fingerprint_tech(
        html="", headers={},
        cookies=[_Cookie("_rails_session")],
        script_urls=[], meta={},
    )
    names = {f.name for f in findings}
    assert "Ruby on Rails" in names


def test_rails_detected_via_phusion_passenger_header():
    findings = fingerprint_tech(
        html="",
        headers={"x-powered-by": "Phusion Passenger"},
        script_urls=[], meta={},
    )
    names = {f.name for f in findings}
    assert "Ruby on Rails" in names


def test_no_signals_returns_empty():
    findings = fingerprint_tech(
        html="<html><body>hello</body></html>",
        headers={},
        script_urls=[],
        meta={},
    )
    assert findings == []


# ---------------------------------------------------------------------------
# Modern JS framework detection
# ---------------------------------------------------------------------------

def test_svelte_via_scoped_class():
    html = '<div class="svelte-abc123">Hello</div>'
    findings = fingerprint_tech(html=html, headers={})
    names = {f.name for f in findings}
    assert "Svelte" in names


def test_sveltekit_via_header():
    findings = fingerprint_tech(
        html="", headers={"x-sveltekit-page": "true"},
    )
    names = {f.name for f in findings}
    assert "SvelteKit" in names


def test_astro_via_meta_generator():
    findings = fingerprint_tech(
        html='<astro-island>hi</astro-island>',
        headers={},
        meta={"generator": "Astro v4.1.0"},
    )
    astro = next(f for f in findings if f.name == "Astro")
    assert astro.version == "4.1.0"
    assert astro.confidence == "medium"


def test_remix_via_html():
    html = '<script>window.__remixContext = {};</script>'
    findings = fingerprint_tech(html=html, headers={})
    names = {f.name for f in findings}
    assert "Remix" in names


def test_nuxt3_payload_marker():
    html = '<div id="__NUXT_PAYLOAD__"></div>'
    findings = fingerprint_tech(html=html, headers={})
    names = {f.name for f in findings}
    assert "Nuxt.js" in names


def test_nextjs_app_router():
    html = '<script id="__NEXT_APP_DATA__" type="application/json"></script>'
    findings = fingerprint_tech(html=html, headers={})
    names = {f.name for f in findings}
    assert "Next.js" in names


# ---------------------------------------------------------------------------
# WAF / security appliance detection
# ---------------------------------------------------------------------------

class _Cookie:
    def __init__(self, name):
        self.name = name


def test_akamai_via_header_and_cookie():
    findings = fingerprint_tech(
        html="",
        headers={"x-akamai-transformed": "9 - 0 pmb=mRUM,3"},
        cookies=[_Cookie("bm_sz")],
    )
    akamai = next(f for f in findings if f.name == "Akamai")
    assert "header:x-akamai-transformed" in akamai.evidence
    assert "cookie" in akamai.evidence


def test_imperva_via_cookie():
    findings = fingerprint_tech(
        html="",
        headers={"x-iinfo": "7-42-0"},
        cookies=[_Cookie("visid_incap_12345")],
    )
    names = {f.name for f in findings}
    assert "Imperva" in names


def test_sucuri_via_header():
    findings = fingerprint_tech(
        html="",
        headers={"x-sucuri-id": "abc123", "server": "Sucuri/Cloudproxy"},
    )
    sucuri = next(f for f in findings if f.name == "Sucuri")
    assert sucuri.confidence == "medium"


def test_f5_bigip_via_cookie():
    findings = fingerprint_tech(
        html="", headers={},
        cookies=[_Cookie("BIGipServerpool_web_443")],
    )
    names = {f.name for f in findings}
    assert "F5 BIG-IP" in names


def test_azure_front_door_via_header():
    findings = fingerprint_tech(
        html="",
        headers={"x-azure-ref": "0abc123def456"},
    )
    names = {f.name for f in findings}
    assert "Azure Front Door" in names
