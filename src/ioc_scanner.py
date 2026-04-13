"""Detect Indicators of Compromise (IoC) in crawled page HTML.

Layer-1 analysis: entirely self-contained, no external API calls.
Runs on the raw HTML that the crawler already fetches.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup, Tag

from .models import IoCFinding

# ---------------------------------------------------------------------------
# 1. Cryptominer detection
# ---------------------------------------------------------------------------

_MINER_DOMAINS: set[str] = {
    "coinhive.com", "coin-hive.com", "authedmine.com",
    "crypto-loot.com", "cryptoloot.pro",
    "jsecoin.com", "webminepool.com",
    "minero.cc", "monerominer.rocks",
    "ppoi.org", "projectpoi.com",
    "2giga.link", "coinerra.com",
    "inwemo.com", "mulifnc.com",
}

_MINER_CONSTRUCTORS = re.compile(
    r"\b(?:CoinHive|CRLT|Client|CryptoLoot|Minero|deepMiner|coinimp)"
    r"\.(?:Anonymous|User|Token|Start)\b",
    re.I,
)


def _check_cryptominers(soup: BeautifulSoup, html: str) -> list[IoCFinding]:
    findings: list[IoCFinding] = []
    # Check <script src="..."> tags
    for tag in soup.find_all("script", src=True):
        src: str = tag["src"]
        try:
            host = (urlparse(src).hostname or "").lower().lstrip("www.")
        except Exception:
            continue
        if host in _MINER_DOMAINS:
            findings.append(IoCFinding(
                ioc_type="cryptominer",
                description=f"Known cryptominer script loaded from {host}",
                evidence=src[:200],
                location="script",
                severity="critical",
            ))

    # Check inline miner constructor patterns
    for m in _MINER_CONSTRUCTORS.finditer(html):
        findings.append(IoCFinding(
            ioc_type="cryptominer",
            description="Cryptominer constructor detected in inline JavaScript",
            evidence=m.group(0),
            location="script",
            severity="critical",
        ))

    return findings


# ---------------------------------------------------------------------------
# 2. Hidden iframe detection
# ---------------------------------------------------------------------------

_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden", re.I,
)

# Known analytics / tracking / advertising platforms that legitimately use
# hidden iframes.  These are NOT indicators of compromise.
_TRUSTED_IFRAME_DOMAINS: set[str] = {
    "googletagmanager.com", "google-analytics.com", "analytics.google.com",
    "www.googletagmanager.com", "www.google-analytics.com",
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "google.com",
    "connect.facebook.net", "facebook.com", "staticxx.facebook.com",
    "platform.twitter.com", "syndication.twitter.com",
    "snap.licdn.com", "platform.linkedin.com",
    "bat.bing.com", "clarity.ms",
    "analytics.tiktok.com",
    "cdn.segment.com",
    "js.hs-analytics.net", "js.hubspot.com",
    "static.hotjar.com", "vars.hotjar.com",
    "widget.intercom.io",
    "player.vimeo.com", "youtube.com", "youtube-nocookie.com",
    "recaptcha.net", "google.com",
}


def _is_trusted_iframe(host: str) -> bool:
    """Return True if *host* belongs to a known analytics/tracking platform."""
    if host in _TRUSTED_IFRAME_DOMAINS:
        return True
    # Also match subdomains of trusted roots (e.g. ns.googletagmanager.com)
    for trusted in _TRUSTED_IFRAME_DOMAINS:
        if host.endswith("." + trusted):
            return True
    return False


def _check_hidden_iframes(soup: BeautifulSoup, page_domain: str) -> list[IoCFinding]:
    findings: list[IoCFinding] = []
    for iframe in soup.find_all("iframe", src=True):
        src: str = iframe.get("src", "")
        if not src or src.startswith(("about:", "javascript:")):
            continue

        try:
            iframe_host = (urlparse(src).hostname or "").lower().lstrip("www.")
        except Exception:
            continue

        # Skip same-domain iframes
        if iframe_host == page_domain:
            continue

        # Skip known analytics / tracking platforms
        if _is_trusted_iframe(iframe_host):
            continue

        is_hidden = False
        # Check dimensional attributes
        width = iframe.get("width", "")
        height = iframe.get("height", "")
        if width in ("0", "1") or height in ("0", "1"):
            is_hidden = True

        # Check inline style
        style = iframe.get("style", "")
        if _HIDDEN_STYLE_RE.search(style):
            is_hidden = True

        if is_hidden:
            findings.append(IoCFinding(
                ioc_type="hidden_iframe",
                description="Hidden iframe loading unknown external content",
                evidence=f"{src[:150]} (width={width}, height={height})",
                location="iframe",
                severity="high",
            ))

    return findings


# ---------------------------------------------------------------------------
# 3. Obfuscated JavaScript detection
# ---------------------------------------------------------------------------

_OBFUSCATION_PATTERNS = [
    (re.compile(r"\beval\s*\(\s*atob\s*\("), "eval(atob(...))"),
    (re.compile(r"\beval\s*\(\s*unescape\s*\("), "eval(unescape(...))"),
    (re.compile(r"\beval\s*\(\s*String\.fromCharCode\s*\("), "eval(String.fromCharCode(...))"),
    (re.compile(r"document\.write\s*\(\s*unescape\s*\("), "document.write(unescape(...))"),
    (re.compile(r"document\.write\s*\(\s*atob\s*\("), "document.write(atob(...))"),
]

# A single page with many eval() calls is suspicious
_EVAL_RE = re.compile(r"\beval\s*\(", re.I)

# Long hex/octal/charcode strings indicate obfuscation
_LONG_ENCODED_RE = re.compile(
    r"(?:(?:\\x[0-9a-f]{2}){20,}|(?:\\u[0-9a-f]{4}){15,}|"
    r"String\.fromCharCode\([0-9,\s]{60,}\))",
    re.I,
)


def _check_obfuscated_js(html: str) -> list[IoCFinding]:
    findings: list[IoCFinding] = []

    # Check for specific obfuscation combos
    for pattern, label in _OBFUSCATION_PATTERNS:
        matches = pattern.findall(html)
        if matches:
            findings.append(IoCFinding(
                ioc_type="obfuscated_js",
                description=f"Obfuscated JavaScript pattern detected: {label}",
                evidence=f"{len(matches)} occurrence(s)",
                location="script",
                severity="high",
            ))

    # Flag excessive eval() usage
    eval_count = len(_EVAL_RE.findall(html))
    if eval_count >= 10:
        findings.append(IoCFinding(
            ioc_type="obfuscated_js",
            description=f"Excessive eval() usage: {eval_count} calls detected",
            evidence=f"{eval_count} eval() calls",
            location="script",
            severity="medium",
        ))

    # Long encoded strings
    for m in _LONG_ENCODED_RE.finditer(html):
        findings.append(IoCFinding(
            ioc_type="obfuscated_js",
            description="Long encoded/escaped string detected (possible payload)",
            evidence=m.group(0)[:80] + "...",
            location="script",
            severity="high",
        ))
        break  # one finding is enough

    return findings


# ---------------------------------------------------------------------------
# 4. SEO spam injection detection
# ---------------------------------------------------------------------------

_SEO_SPAM_KEYWORDS = re.compile(
    r"\b(?:buy\s+viagra|cheap\s+cialis|online\s+casino|free\s+slots|"
    r"payday\s+loan|poker\s+online|buy\s+cheap|pharma\s+online|"
    r"gambling\s+online|adult\s+dating|essay\s+writing\s+service)\b",
    re.I,
)

_HIDDEN_ELEM_STYLE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"position\s*:\s*absolute[^\"]*(?:left|top)\s*:\s*-\d{3,}",
    re.I,
)


def _check_seo_spam(soup: BeautifulSoup, page_domain: str) -> list[IoCFinding]:
    findings: list[IoCFinding] = []
    spam_links: list[str] = []

    for tag in soup.find_all(["div", "span", "p", "section"]):
        style = tag.get("style", "")
        if not _HIDDEN_ELEM_STYLE.search(style):
            continue

        # This element is hidden – check for external links inside
        for a in tag.find_all("a", href=True):
            href = a["href"]
            try:
                host = (urlparse(href).hostname or "").lower().lstrip("www.")
            except Exception:
                continue
            if host and host != page_domain:
                spam_links.append(host)

    if len(spam_links) >= 3:
        unique = sorted(set(spam_links))[:5]
        findings.append(IoCFinding(
            ioc_type="seo_spam",
            description=f"{len(spam_links)} hidden external links detected (SEO spam injection)",
            evidence=", ".join(unique) + ("..." if len(set(spam_links)) > 5 else ""),
            location="body",
            severity="high",
        ))

    # Also check for spam keywords in hidden elements
    for tag in soup.find_all(style=_HIDDEN_ELEM_STYLE):
        text = tag.get_text(" ", strip=True)
        if _SEO_SPAM_KEYWORDS.search(text):
            findings.append(IoCFinding(
                ioc_type="seo_spam",
                description="Spam keywords found in hidden HTML element",
                evidence=text[:100],
                location="body",
                severity="high",
            ))
            break  # one finding is enough

    return findings


# ---------------------------------------------------------------------------
# 5. Credential harvesting (phishing forms)
# ---------------------------------------------------------------------------

def _check_credential_harvesting(soup: BeautifulSoup, page_domain: str) -> list[IoCFinding]:
    findings: list[IoCFinding] = []

    for form in soup.find_all("form"):
        # Does this form have a password field?
        has_password = bool(form.find("input", {"type": "password"}))
        if not has_password:
            continue

        action = (form.get("action") or "").strip()
        if not action or action.startswith(("#", "/")):
            continue  # relative or same-page – probably legitimate

        try:
            action_host = (urlparse(action).hostname or "").lower().lstrip("www.")
        except Exception:
            continue

        if action_host and action_host != page_domain:
            findings.append(IoCFinding(
                ioc_type="credential_harvest",
                description="Login form submits credentials to a different domain",
                evidence=f"Form action: {action[:150]} (page domain: {page_domain})",
                location="form",
                severity="critical",
            ))

    return findings


# ---------------------------------------------------------------------------
# 6. Defacement markers
# ---------------------------------------------------------------------------

_DEFACEMENT_RE = re.compile(
    r"(?:hacked\s+by|defaced\s+by|owned\s+by|pwned\s+by|"
    r"greetz\s+to|sh[e3]ll\s+by|rooted\s+by|"
    r"cyber\s*(?:army|team|ghost|warrior))\b",
    re.I,
)


def _check_defacement(soup: BeautifulSoup, html: str) -> list[IoCFinding]:
    findings: list[IoCFinding] = []

    # Check <title>
    title_tag = soup.find("title")
    if title_tag:
        title_text = title_tag.get_text(strip=True)
        if _DEFACEMENT_RE.search(title_text):
            findings.append(IoCFinding(
                ioc_type="defacement",
                description="Defacement signature detected in page title",
                evidence=title_text[:150],
                location="body",
                severity="critical",
            ))

    # Check headings and body text
    for tag in soup.find_all(["h1", "h2", "h3", "marquee"]):
        text = tag.get_text(strip=True)
        if _DEFACEMENT_RE.search(text):
            findings.append(IoCFinding(
                ioc_type="defacement",
                description=f"Defacement signature detected in <{tag.name}> tag",
                evidence=text[:150],
                location="body",
                severity="critical",
            ))
            break  # one heading match is enough

    return findings


# ---------------------------------------------------------------------------
# 7. Suspicious external scripts
# ---------------------------------------------------------------------------

_SUSPICIOUS_TLDS: set[str] = {
    ".xyz", ".tk", ".top", ".pw", ".cc", ".buzz",
    ".gq", ".ml", ".cf", ".ga", ".click", ".loan",
    ".work", ".date", ".racing", ".win", ".download",
    ".bid", ".stream", ".trade", ".accountant",
}


def _looks_random(domain: str) -> bool:
    """Heuristic: domains with very few vowels relative to length are suspicious."""
    name = domain.split(".")[0]
    if len(name) < 4:
        return False
    vowels = sum(1 for c in name.lower() if c in "aeiou")
    return vowels / len(name) < 0.15 and len(name) >= 6


def _check_suspicious_scripts(soup: BeautifulSoup, page_domain: str) -> list[IoCFinding]:
    findings: list[IoCFinding] = []
    seen: set[str] = set()

    for tag in soup.find_all("script", src=True):
        src: str = tag["src"]
        try:
            parsed = urlparse(src)
            host = (parsed.hostname or "").lower().lstrip("www.")
        except Exception:
            continue

        if not host or host == page_domain or host in seen:
            continue
        seen.add(host)

        is_suspicious = False
        reason = ""

        # Check TLD
        for tld in _SUSPICIOUS_TLDS:
            if host.endswith(tld):
                is_suspicious = True
                reason = f"Suspicious TLD ({tld})"
                break

        # Check for random-looking domain
        if not is_suspicious and _looks_random(host):
            is_suspicious = True
            reason = "Domain name appears randomly generated"

        if is_suspicious:
            findings.append(IoCFinding(
                ioc_type="suspicious_script",
                description=f"External script loaded from suspicious domain: {reason}",
                evidence=src[:200],
                location="script",
                severity="medium",
            ))

    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_ioc(html: str, page_url: str) -> list[IoCFinding]:
    """Scan *html* for indicators of compromise.

    Returns a list of :class:`IoCFinding`. This is a Layer-1 analysis —
    purely content-based, no external API calls.
    """
    soup = BeautifulSoup(html, "html.parser")

    try:
        page_domain = (urlparse(page_url).hostname or "").lower().lstrip("www.")
    except Exception:
        page_domain = ""

    findings: list[IoCFinding] = []
    findings.extend(_check_cryptominers(soup, html))
    findings.extend(_check_hidden_iframes(soup, page_domain))
    findings.extend(_check_obfuscated_js(html))
    findings.extend(_check_seo_spam(soup, page_domain))
    findings.extend(_check_credential_harvesting(soup, page_domain))
    findings.extend(_check_defacement(soup, html))
    findings.extend(_check_suspicious_scripts(soup, page_domain))

    return findings
