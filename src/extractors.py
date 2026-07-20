"""Extract contacts, phone numbers, social profiles, and links from HTML."""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Comment

from .models import ContactInfo, LinkInfo


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
)

_PHONE_RE = re.compile(
    r"(?:\+?\d{1,3}[\s\-]?)?"         # optional country code
    r"(?:\(?\d{1,4}\)?[\s\-]?)?"       # optional area code
    r"\d{2,4}[\s\-]\d{2,4}(?:[\s\-]\d{2,4})?",
)

# Minimum digits to consider something a real phone number
_MIN_PHONE_DIGITS = 7

_SOCIAL_DOMAINS = {
    "twitter.com", "x.com",
    "facebook.com", "fb.com",
    "linkedin.com",
    "instagram.com",
    "github.com",
    "youtube.com",
    "tiktok.com",
    "pinterest.com",
    "reddit.com",
    "t.me",
    "mastodon.social",
}

# Skip common false-positive emails
_EMAIL_BLOCKLIST = {
    "example@example.com",
    "user@example.com",
    "name@domain.com",
    "email@example.com",
}


def _digit_count(s: str) -> int:
    return sum(c.isdigit() for c in s)


_YEAR_RANGE_RE = re.compile(
    r"(?:19|20)\d{2}[\s\-/](?:19|20)\d{2}"  # e.g. "1977-2007"
)
_TRAILING_YEAR_RE = re.compile(
    r"[\s\-](?:19|20)\d{2}$"  # ends with a 4-digit year
)


def _normalise_phone(raw: str) -> str | None:
    """Return a cleaned phone string or *None* if it looks like a false positive."""
    stripped = raw.strip()
    if "." in stripped:
        return None
    if _YEAR_RANGE_RE.search(stripped):
        return None
    digits = re.sub(r"\D", "", stripped)
    if len(digits) < _MIN_PHONE_DIGITS or len(digits) > 15:
        return None
    if _TRAILING_YEAR_RE.search(stripped) and len(digits) <= 8:
        return None
    if digits.startswith(("19", "20")) and 1900 <= int(digits[:4]) <= 2099:
        if len(digits) <= 10 and not stripped.startswith("+"):
            return None
    if stripped.startswith("+") and len(digits) < 10:
        return None
    return stripped


# TLD → international dialling code (used to canonicalise national numbers when
# the domain gives us a default region). Small, extensible map — unknown TLDs
# fall through to best-effort.
_TLD_TO_CC = {
    "ie": ("353", "IE"), "uk": ("44", "GB"), "gb": ("44", "GB"),
    "us": ("1", "US"), "ca": ("1", "CA"), "au": ("61", "AU"),
    "de": ("49", "DE"), "fr": ("33", "FR"), "es": ("34", "ES"),
    "it": ("39", "IT"), "nl": ("31", "NL"), "be": ("32", "BE"),
    "pt": ("351", "PT"), "se": ("46", "SE"), "no": ("47", "NO"),
    "dk": ("45", "DK"), "fi": ("358", "FI"), "pl": ("48", "PL"),
    "nz": ("64", "NZ"), "za": ("27", "ZA"), "in": ("91", "IN"),
}


def region_for_tld(tld: str) -> tuple[str, str]:
    """Return (dialling_code, ISO_country) for a TLD, or ('', '') if unknown."""
    return _TLD_TO_CC.get((tld or "").lower().lstrip("."), ("", ""))


def normalize_phone_e164(raw: str, default_cc: str = "", default_country: str = "") -> dict:
    """Best-effort E.164 normalisation without a phone library.

    Returns {raw_value, normalized_value, country, confidence}. `confidence` is
    'high' when a country code is explicit (+, 00) or supplied via the domain
    region; 'low' for a bare national number we can't anchor to a country (these
    should not be counted as confident unique numbers).
    """
    cleaned = _normalise_phone(raw)
    if not cleaned:
        return {"raw_value": raw, "normalized_value": None, "country": "", "confidence": "low"}

    has_cc = cleaned.startswith("+") or cleaned.strip().startswith("00")
    digits = re.sub(r"\D", "", cleaned)
    if cleaned.strip().startswith("00"):
        digits = digits[2:]

    if has_cc:
        return {
            "raw_value": raw,
            "normalized_value": "+" + digits,
            "country": default_country,  # explicit-CC country needs a CC table; best-effort
            "confidence": "high",
        }

    if default_cc:
        # The number may already carry the country code without a '+'
        # (e.g. "353 1 6510 300"). Detect that before prepending it again.
        if digits.startswith(default_cc) and len(digits) > len(default_cc) + 4:
            return {
                "raw_value": raw,
                "normalized_value": "+" + digits,
                "country": default_country,
                "confidence": "high",
            }
        national = digits[1:] if digits.startswith("0") else digits
        return {
            "raw_value": raw,
            "normalized_value": "+" + default_cc + national,
            "country": default_country,
            "confidence": "high",
        }

    # No country context — canonicalise formatting only; treat as low confidence
    # so bare/partial national fragments don't inflate the unique-number count.
    return {
        "raw_value": raw,
        "normalized_value": "+" + digits if len(digits) >= 10 else None,
        "country": "",
        "confidence": "low",
    }


# Path/query fragments that mark a social URL as a share/tracking endpoint
# rather than an organisation-owned profile.
_SHARE_PATH_MARKERS = (
    "/sharer", "/share", "/intent", "/dialog", "/shareArticle", "/submit",
    "/pin/create", "/offsite", "/tweet", "/share_channel",
)
_SHARE_QUERY_MARKERS = ("u=", "url=", "text=", "mini=", "title=")
_TRACKING_HOSTS = {"t.co", "lnkd.in", "fb.me"}


def classify_social_url(url: str) -> str:
    """Classify a social URL: organisation_profile / share_link / tracking_link /
    embedded_widget / unknown. Share/intent endpoints are NOT owned profiles."""
    try:
        parsed = urlparse(url)
    except Exception:
        return "unknown"
    host = (parsed.hostname or "").lower()
    if host.startswith("www."):
        host = host[4:]
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()

    if host in _TRACKING_HOSTS:
        return "tracking_link"
    if any(m.lower() in path for m in _SHARE_PATH_MARKERS):
        return "share_link"
    if any(q in query for q in _SHARE_QUERY_MARKERS):
        return "share_link"
    if "/embed" in path or "/plugins/" in path or "/widgets/" in path:
        return "embedded_widget"
    if path in ("", "/"):
        return "unknown"
    return "organisation_profile"


def extract_contacts(soup: BeautifulSoup, raw_html: str) -> ContactInfo:
    """Extract emails, phone numbers, and social-media profile URLs."""
    text = soup.get_text(separator=" ", strip=True)

    # --- Emails ---
    emails: set[str] = set()
    for m in _EMAIL_RE.finditer(text):
        email = m.group(0).lower()
        if email not in _EMAIL_BLOCKLIST:
            emails.add(email)
    # Also check mailto: links
    for a_tag in soup.find_all("a", href=True):
        href: str = a_tag["href"]
        if href.startswith("mailto:"):
            addr = href.removeprefix("mailto:").split("?")[0].strip().lower()
            if addr and addr not in _EMAIL_BLOCKLIST:
                emails.add(addr)

    # --- Phone numbers ---
    phones: set[str] = set()
    # Check tel: links first (most reliable)
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        if href.startswith("tel:"):
            num = href.removeprefix("tel:").strip()
            cleaned = _normalise_phone(num)
            if cleaned:
                phones.add(cleaned)
    # Regex scan on visible text
    for m in _PHONE_RE.finditer(text):
        cleaned = _normalise_phone(m.group(0))
        if cleaned:
            phones.add(cleaned)

    # --- Social profiles ---
    socials: set[str] = set()
    for a_tag in soup.find_all("a", href=True):
        href = a_tag["href"]
        try:
            parsed = urlparse(href)
            host = (parsed.hostname or "").lower().lstrip("www.")
            if host in _SOCIAL_DOMAINS and parsed.path not in ("", "/"):
                socials.add(href)
        except Exception:
            continue

    return ContactInfo(
        emails=sorted(emails),
        phone_numbers=sorted(phones),
        social_profiles=sorted(socials),
    )


def extract_links(
    soup: BeautifulSoup,
    page_url: str,
) -> list[LinkInfo]:
    """Return all links found on the page, classified as internal or external."""
    parsed_base = urlparse(page_url)
    base_domain = (parsed_base.hostname or "").lower().lstrip("www.")
    links: list[LinkInfo] = []
    seen: set[str] = set()

    for tag in soup.find_all("a", href=True):
        raw_href: str = tag["href"].strip()
        if not raw_href or raw_href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue

        absolute = urljoin(page_url, raw_href)
        if absolute in seen:
            continue
        seen.add(absolute)

        try:
            parsed = urlparse(absolute)
        except Exception:
            continue

        if parsed.scheme not in ("http", "https"):
            continue

        link_host = (parsed.hostname or "").lower().lstrip("www.")
        link_type = "internal" if link_host == base_domain else "external"
        anchor = tag.get_text(strip=True)[:200]
        links.append(LinkInfo(url=absolute, anchor_text=anchor, link_type=link_type))

    return links


def extract_page_metadata(soup: BeautifulSoup) -> tuple[str, str, str]:
    """Return (title, meta_description, content_snippet)."""
    title = ""
    title_tag = soup.find("title")
    if title_tag:
        title = title_tag.get_text(strip=True)[:300]

    meta_desc = ""
    meta_tag = soup.find("meta", attrs={"name": re.compile(r"description", re.I)})
    if meta_tag and meta_tag.get("content"):
        meta_desc = meta_tag["content"].strip()[:500]

    text = soup.get_text(separator=" ", strip=True)
    snippet = text[:500] if text else ""

    return title, meta_desc, snippet
