"""Shared helpers for external-link normalisation and filtering."""

from __future__ import annotations

from urllib.parse import urlparse

_SOCIAL_HOSTS = frozenset({
    "twitter.com", "x.com", "facebook.com", "fb.com", "linkedin.com",
    "instagram.com", "github.com", "youtube.com", "tiktok.com",
    "pinterest.com", "reddit.com", "t.me", "mastodon.social",
})

MAX_FOUND_ON = 5


def normalise_ext_url(url: str) -> str:
    """Normalise an external URL for deduplication (strip trailing slash, www)."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower().lstrip("www.")
    path = parsed.path.rstrip("/") or ""
    qs = f"?{parsed.query}" if parsed.query else ""
    frag = f"#{parsed.fragment}" if parsed.fragment else ""
    return f"{parsed.scheme}://{host}{path}{qs}{frag}"


def is_social_url(url: str) -> bool:
    """Return True if the URL points to a known social media platform."""
    try:
        host = (urlparse(url).hostname or "").lower().lstrip("www.")
        return host in _SOCIAL_HOSTS
    except Exception:
        return False
