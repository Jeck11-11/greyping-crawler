"""Detect exposed secrets, API keys, credentials, and sensitive data in page source."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator

from .models import SecretFinding


@dataclass(frozen=True)
class _Pattern:
    name: str
    secret_type: str
    regex: re.Pattern[str]
    severity: str = "high"


# ---------------------------------------------------------------------------
# Pattern library – covers OWASP-style leaks commonly found in HTML/JS/comments
# ---------------------------------------------------------------------------
_PATTERNS: list[_Pattern] = [
    # AWS (AKIA = long-term, ASIA = temporary STS credentials)
    _Pattern("aws_access_key_id", "aws_access_key",
             re.compile(r"(?:(?:AKIA|ASIA)[0-9A-Z]{16})")),
    _Pattern("aws_secret_access_key", "aws_secret_key",
             re.compile(r"""(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?""", re.I)),
    # Google
    _Pattern("google_api_key", "google_api_key",
             re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    _Pattern("google_oauth_token", "google_oauth",
             re.compile(r"ya29\.[0-9A-Za-z\-_]+")),
    # GitHub
    _Pattern("github_token", "github_token",
             re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}")),
    # Slack
    _Pattern("slack_token", "slack_token",
             re.compile(r"xox[bpors]-[0-9]{10,}-[0-9A-Za-z]{10,}")),
    _Pattern("slack_webhook", "slack_webhook",
             re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    # Stripe (bounded length to reduce false positives)
    _Pattern("stripe_secret_key", "stripe_key",
             re.compile(r"sk_live_[0-9a-zA-Z]{24,99}")),
    _Pattern("stripe_publishable_key", "stripe_key",
             re.compile(r"pk_live_[0-9a-zA-Z]{24,99}")),
    # Twilio
    _Pattern("twilio_api_key", "twilio_key",
             re.compile(r"SK[0-9a-fA-F]{32}")),
    # Mailgun
    _Pattern("mailgun_api_key", "mailgun_key",
             re.compile(r"key-[0-9a-zA-Z]{32}")),
    # SendGrid
    _Pattern("sendgrid_api_key", "sendgrid_key",
             re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}")),
    # Heroku – require a keyword so bare UUIDs (CSS IDs, tracking pixels, etc.) don't match
    _Pattern("heroku_api_key", "heroku_key",
             re.compile(r"""(?:heroku[_\s-]*(?:api[_\s-]*)?key|HEROKU_API_KEY)\s*[:=]\s*['"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['"]?""", re.I)),
    # Private keys
    _Pattern("private_key", "private_key",
             re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----")),
    # Generic database connection strings (require user:pass@ to reduce false positives)
    _Pattern("database_url", "database_credential",
             re.compile(r"""(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://[^:@\s'"<>]+:[^@\s'"<>]+@[^\s'"<>]{5,200}""", re.I)),
    # Generic password assignments
    _Pattern("generic_password", "generic_password",
             re.compile(r"""(?:password|passwd|pwd|secret|token|api_key|apikey|access_key)\s*[:=]\s*['"]([^'"]{8,})['"]""", re.I)),
    # Generic Bearer tokens
    _Pattern("bearer_token", "bearer_token",
             re.compile(r"""[Bb]earer\s+[A-Za-z0-9\-_.~+/]+=*""")),
    # JWT tokens
    _Pattern("jwt_token", "jwt_token",
             re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    # Firebase
    _Pattern("firebase_url", "firebase_config",
             re.compile(r"https://[a-z0-9-]+\.firebaseio\.com")),
    # Azure
    _Pattern("azure_storage_key", "azure_key",
             re.compile(r"""AccountKey=[A-Za-z0-9+/=]{44,}""")),
    # Slack bot/user tokens (xoxb = bot, xoxp = user)
    _Pattern("slack_bot_token", "slack_token",
             re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,32}")),
    # Twilio
    _Pattern("twilio_account_sid", "twilio_credential",
             re.compile(r"AC[0-9a-f]{32}", re.I)),
]


def _redact(value: str, visible_chars: int = 4) -> str:
    """Return a redacted preview showing only the first and last *visible_chars*."""
    if len(value) <= visible_chars * 2 + 3:
        return "*" * len(value)
    return f"{value[:visible_chars]}...{value[-visible_chars:]}"


def _classify_location(source: str, match_start: int) -> str:
    """Heuristically determine where in the HTML the match lives."""
    # Look backwards from the match position for context clues
    preceding = source[max(0, match_start - 200):match_start].lower()
    if "<!--" in preceding and "-->" not in preceding.split("<!--")[-1]:
        return "html_comment"
    if "<script" in preceding and "</script>" not in preceding.split("<script")[-1]:
        return "script"
    if "<style" in preceding and "</style>" not in preceding.split("<style")[-1]:
        return "style"
    if "meta" in preceding:
        return "meta"
    return "body"


def scan_secrets(source: str) -> list[SecretFinding]:
    """Scan *source* (raw HTML / JS) and return a list of secret findings."""
    findings: list[SecretFinding] = []
    seen: set[str] = set()

    for pattern in _PATTERNS:
        for match in pattern.regex.finditer(source):
            # Prefer the first capture group if present, else the full match
            value = match.group(1) if match.lastindex else match.group(0)
            dedup_key = (pattern.name, value)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append(
                SecretFinding(
                    secret_type=pattern.secret_type,
                    matched_pattern=pattern.name,
                    value_preview=_redact(value),
                    location=_classify_location(source, match.start()),
                    severity=pattern.severity,
                )
            )

    return findings
