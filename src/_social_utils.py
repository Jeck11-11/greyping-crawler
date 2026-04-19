"""Shared social-platform detection used by the orchestrator and content router."""

from __future__ import annotations

from urllib.parse import urlparse

SOCIAL_PLATFORM_MAP = {
    "twitter.com": "Twitter", "x.com": "Twitter/X",
    "facebook.com": "Facebook", "fb.com": "Facebook",
    "linkedin.com": "LinkedIn", "instagram.com": "Instagram",
    "github.com": "GitHub", "youtube.com": "YouTube",
    "tiktok.com": "TikTok", "pinterest.com": "Pinterest",
    "reddit.com": "Reddit", "t.me": "Telegram",
    "mastodon.social": "Mastodon",
}


def detect_platform(url: str) -> str:
    """Return the platform name for a social URL, or empty string."""
    try:
        host = (urlparse(url).hostname or "").lower().lstrip("www.")
        return SOCIAL_PLATFORM_MAP.get(host, "")
    except Exception:
        return ""
