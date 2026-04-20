"""Wappalyzer-style technology fingerprinter.

Uses a curated built-in signature dictionary covering the most common web
stacks.  Each signature may match against headers, HTML, <meta> tags, cookies
and loaded <script src> URLs.  Version extraction is supported via named
regex capture groups.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from .models import TechFinding

# ---------------------------------------------------------------------------
# Signature database.  Each entry is a dict with optional keys:
#   categories    — list[str]
#   headers       — {header_name: pattern_with_optional_(?P<version>...)}
#   html          — list[pattern] matched against raw HTML
#   meta          — {meta_name: pattern}
#   cookies       — list[cookie_name_pattern]
#   scripts       — list[pattern] matched against <script src> URLs
#   implies       — list[other_tech_names] to also add when this hits
# ---------------------------------------------------------------------------

SIGNATURES: dict[str, dict[str, Any]] = {
    # --- CMS / app frameworks -------------------------------------------------
    "WordPress": {
        "categories": ["cms"],
        "html": [r"/wp-content/", r"/wp-includes/", r"wp-json"],
        "meta": {"generator": r"WordPress(?:\s*(?P<version>[\d.]+))?"},
    },
    "Drupal": {
        "categories": ["cms"],
        "html": [r"Drupal\.settings", r"/sites/default/files/"],
        "meta": {"generator": r"Drupal\s*(?P<version>\d+)?"},
        "headers": {"x-generator": r"Drupal\s*(?P<version>\d+)?"},
    },
    "Joomla": {
        "categories": ["cms"],
        "meta": {"generator": r"Joomla!?\s*-?\s*(?P<version>[\d.]+)?"},
    },
    "Shopify": {
        "categories": ["ecommerce"],
        "headers": {"x-shopid": r".+", "x-shopify-stage": r".+"},
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
    },
    "Wix": {
        "categories": ["website_builder"],
        "headers": {"x-wix-request-id": r".+"},
        "meta": {"generator": r"Wix\.com"},
        "html": [r"static\.wixstatic\.com"],
    },
    "Squarespace": {
        "categories": ["website_builder"],
        "html": [r"static\.squarespace\.com", r"Static\.SQUARESPACE_CONTEXT"],
    },
    "Webflow": {
        "categories": ["website_builder"],
        "html": [r"data-wf-site=", r"assets\.website-files\.com"],
    },
    "Ghost": {
        "categories": ["cms"],
        "meta": {"generator": r"Ghost\s*(?P<version>[\d.]+)?"},
    },
    # --- JS frameworks --------------------------------------------------------
    "React": {
        "categories": ["js_framework"],
        "html": [r"__REACT_DEVTOOLS", r"data-reactroot", r"data-reactid"],
        "scripts": [r"/react(?:\.production|\.development)?(?:\.min)?\.js"],
    },
    "Vue.js": {
        "categories": ["js_framework"],
        "html": [r"__VUE_HMR_RUNTIME__", r"data-v-[0-9a-f]{6,}"],
        "scripts": [r"/vue(?:\.runtime)?(?:\.min)?\.js"],
    },
    "Angular": {
        "categories": ["js_framework"],
        "html": [r"ng-version=\"(?P<version>[^\"]+)\"", r"ng-app"],
    },
    "Next.js": {
        "categories": ["js_framework"],
        "html": [r"__NEXT_DATA__", r"__NEXT_APP_DATA__", r"/_next/static/"],
        "headers": {"x-powered-by": r"Next\.js\s*(?P<version>[\d.]+)?"},
    },
    "Nuxt.js": {
        "categories": ["js_framework"],
        "html": [r"window\.__NUXT__", r"__NUXT_PAYLOAD__", r"/_nuxt/"],
    },
    "jQuery": {
        "categories": ["js_library"],
        "scripts": [r"/jquery[-.](?P<version>[\d.]+)(?:\.min)?\.js", r"/jquery\.min\.js"],
    },
    "Bootstrap": {
        "categories": ["ui_framework"],
        "html": [r"bootstrap(?:\.min)?\.css", r"class=\"[^\"]*\b(?:container|navbar|btn-primary)\b"],
        "scripts": [r"/bootstrap(?:\.bundle)?(?:\.min)?\.js"],
    },
    "Tailwind CSS": {
        "categories": ["ui_framework"],
        "html": [r"class=\"[^\"]*\b(?:flex|grid|text-gray-\d{3}|bg-(?:white|black|gray-\d{3}))\b[^\"]*\""],
    },
    # --- Backend languages / frameworks ---------------------------------------
    "Laravel": {
        "categories": ["backend_framework"],
        "cookies": [r"^laravel_session$"],
    },
    "Django": {
        "categories": ["backend_framework"],
        "cookies": [r"^csrftoken$"],
    },
    "Ruby on Rails": {
        "categories": ["backend_framework"],
        "cookies": [r"^_rails_session$"],
        "headers": {"x-powered-by": r"Phusion Passenger"},
    },
    "Express": {
        "categories": ["backend_framework"],
        "headers": {"x-powered-by": r"Express"},
    },
    "PHP": {
        "categories": ["language"],
        "headers": {"x-powered-by": r"PHP/?(?P<version>[\d.]+)?"},
        "cookies": [r"^PHPSESSID$"],
    },
    "ASP.NET": {
        "categories": ["backend_framework"],
        "headers": {
            "x-aspnet-version": r"(?P<version>[\d.]+)",
            "x-powered-by": r"ASP\.NET",
        },
        "cookies": [r"^ASP\.NET_SessionId$"],
    },
    # --- Web servers ----------------------------------------------------------
    "Nginx": {
        "categories": ["webserver"],
        "headers": {"server": r"nginx(?:/(?P<version>[\d.]+))?"},
    },
    "Apache": {
        "categories": ["webserver"],
        "headers": {"server": r"Apache(?:/(?P<version>[\d.]+))?"},
    },
    "Microsoft-IIS": {
        "categories": ["webserver"],
        "headers": {"server": r"Microsoft-IIS(?:/(?P<version>[\d.]+))?"},
    },
    "LiteSpeed": {
        "categories": ["webserver"],
        "headers": {"server": r"LiteSpeed"},
    },
    # --- CDN / hosting --------------------------------------------------------
    "Cloudflare": {
        "categories": ["cdn"],
        "headers": {"cf-ray": r".+", "cf-cache-status": r".+"},
        "cookies": [r"^__cf_bm$", r"^__cfduid$"],
    },
    "Fastly": {
        "categories": ["cdn"],
        "headers": {"x-served-by": r"cache-.+", "x-fastly-.+": r".+"},
    },
    "Varnish": {
        "categories": ["caching"],
        "headers": {"x-varnish": r".+", "via": r".*varnish"},
    },
    "AWS CloudFront": {
        "categories": ["cdn"],
        "headers": {"via": r".*CloudFront", "x-amz-cf-id": r".+"},
    },
    "Vercel": {
        "categories": ["paas"],
        "headers": {"server": r"Vercel", "x-vercel-id": r".+"},
    },
    "Netlify": {
        "categories": ["paas"],
        "headers": {"server": r"Netlify", "x-nf-request-id": r".+"},
    },
    "GitHub Pages": {
        "categories": ["paas"],
        "headers": {"server": r"GitHub\.com", "x-github-request-id": r".+"},
    },
    "Heroku": {
        "categories": ["paas"],
        "headers": {"via": r".*Heroku", "server": r"Cowboy"},
    },
    # --- Analytics / marketing ------------------------------------------------
    "Google Analytics": {
        "categories": ["analytics"],
        "scripts": [r"google-analytics\.com/(?:ga|analytics)\.js", r"googletagmanager\.com/gtag/js"],
    },
    "Google Tag Manager": {
        "categories": ["tag_management"],
        "scripts": [r"googletagmanager\.com/gtm\.js"],
        "html": [r"GTM-[A-Z0-9]+"],
    },
    "Hotjar": {
        "categories": ["analytics"],
        "scripts": [r"static\.hotjar\.com/c/hotjar-"],
    },
    "Segment": {
        "categories": ["analytics"],
        "scripts": [r"cdn\.segment\.com/analytics\.js"],
    },
    "Intercom": {
        "categories": ["support_chat"],
        "scripts": [r"widget\.intercom\.io"],
    },
    "Stripe": {
        "categories": ["payment"],
        "scripts": [r"js\.stripe\.com/v[23]/"],
    },
    "reCAPTCHA": {
        "categories": ["captcha"],
        "scripts": [r"www\.google\.com/recaptcha", r"recaptcha\.net"],
    },
    # --- Modern JS frameworks ------------------------------------------------
    "Svelte": {
        "categories": ["js_framework"],
        "html": [r"svelte-[a-z0-9]", r"__svelte"],
    },
    "SvelteKit": {
        "categories": ["js_framework"],
        "html": [r"__sveltekit", r"_app/immutable/"],
        "headers": {"x-sveltekit-page": r".+"},
    },
    "Astro": {
        "categories": ["js_framework"],
        "html": [r"astro-island", r"data-astro-cid-"],
        "meta": {"generator": r"Astro\s*v?(?P<version>[\d.]+)?"},
    },
    "Remix": {
        "categories": ["js_framework"],
        "html": [r"__remix", r"__remixContext"],
        "scripts": [r"entry\.client"],
    },
    # --- WAF / security appliances -------------------------------------------
    "Akamai": {
        "categories": ["cdn", "waf"],
        "headers": {"x-akamai-transformed": r".+"},
        "cookies": [r"^AkaSid$", r"^bm_sz$"],
    },
    "Imperva": {
        "categories": ["cdn", "waf"],
        "headers": {"x-iinfo": r".+"},
        "cookies": [r"^visid_incap_\d+$", r"^incap_ses_\d+_\d+$"],
    },
    "Sucuri": {
        "categories": ["cdn", "waf"],
        "headers": {"x-sucuri-id": r".+", "server": r"Sucuri"},
    },
    "F5 BIG-IP": {
        "categories": ["waf"],
        "cookies": [r"^BIGipServer.+$"],
        "headers": {"server": r"BIG-?IP"},
    },
    "Azure Front Door": {
        "categories": ["cdn", "waf"],
        "headers": {"x-azure-ref": r".+"},
    },
}


# ---------------------------------------------------------------------------
# Matcher
# ---------------------------------------------------------------------------

def _compile_all() -> dict[str, dict[str, Any]]:
    compiled: dict[str, dict[str, Any]] = {}
    for name, sig in SIGNATURES.items():
        c: dict[str, Any] = {"categories": sig.get("categories", [])}
        if "headers" in sig:
            c["headers"] = {k.lower(): re.compile(v, re.I) for k, v in sig["headers"].items()}
        if "html" in sig:
            c["html"] = [re.compile(p, re.I) for p in sig["html"]]
        if "meta" in sig:
            c["meta"] = {k.lower(): re.compile(v, re.I) for k, v in sig["meta"].items()}
        if "cookies" in sig:
            c["cookies"] = [re.compile(p, re.I) for p in sig["cookies"]]
        if "scripts" in sig:
            c["scripts"] = [re.compile(p, re.I) for p in sig["scripts"]]
        compiled[name] = c
    return compiled


_COMPILED = _compile_all()


def _confidence(evidence: list[str]) -> str:
    if len(evidence) >= 3:
        return "high"
    if len(evidence) == 2:
        return "medium"
    return "low"


def fingerprint_tech(
    html: str,
    headers: dict[str, str],
    cookies: Iterable[Any] = (),
    script_urls: Iterable[str] = (),
    meta: dict[str, str] | None = None,
) -> list[TechFinding]:
    """Match every built-in signature against the inputs.

    Arguments are all optional where possible so the caller can pass only what
    it has; for example a headers-only probe can fingerprint the webserver
    without providing HTML.
    """
    meta = {k.lower(): v for k, v in (meta or {}).items()}
    headers_lc = {k.lower(): v for k, v in (headers or {}).items()}
    cookie_names = [getattr(c, "name", str(c)) for c in cookies]
    scripts = list(script_urls or [])
    html_sample = html[:200_000] if html else ""

    findings: list[TechFinding] = []
    for name, sig in _COMPILED.items():
        evidence: list[str] = []
        version: str | None = None

        for h_name, pat in sig.get("headers", {}).items():
            val = headers_lc.get(h_name, "")
            if val and (m := pat.search(val)):
                evidence.append(f"header:{h_name}")
                version = version or _version_from_match(m)

        for pat in sig.get("html", []):
            if html_sample and (m := pat.search(html_sample)):
                evidence.append("html")
                version = version or _version_from_match(m)
                break  # one HTML hit per tech is enough

        for m_name, pat in sig.get("meta", {}).items():
            val = meta.get(m_name, "")
            if val and (m := pat.search(val)):
                evidence.append(f"meta:{m_name}")
                version = version or _version_from_match(m)

        for pat in sig.get("cookies", []):
            if any(pat.search(n) for n in cookie_names):
                evidence.append("cookie")
                break

        for pat in sig.get("scripts", []):
            for src in scripts:
                if m := pat.search(src):
                    evidence.append("script")
                    version = version or _version_from_match(m)
                    break
            if "script" in evidence:
                break

        if evidence:
            findings.append(TechFinding(
                name=name,
                categories=sig.get("categories", []),
                version=version,
                confidence=_confidence(evidence),
                evidence=evidence,
            ))

    return findings


def _version_from_match(match: re.Match) -> str | None:
    try:
        v = match.group("version")
        return v or None
    except (IndexError, KeyError):
        return None
