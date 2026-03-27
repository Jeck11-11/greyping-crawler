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
    r"(?:\+?\d{1,3}[\s\-.]?)?"        # optional country code
    r"(?:\(?\d{1,4}\)?[\s\-.]?)?"      # optional area code
    r"\d{2,4}[\s\-.]?\d{2,4}[\s\-.]?\d{2,4}",
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


def _normalise_phone(raw: str) -> str | None:
    """Return a cleaned phone string or *None* if it looks like a false positive."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) < _MIN_PHONE_DIGITS or len(digits) > 15:
        return None
    return raw.strip()


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
