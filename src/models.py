"""Data models for the OSINT reconnaissance API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    """Payload accepted by POST /scan."""

    targets: list[str] = Field(
        ...,
        min_length=1,
        description="One or more domain URLs to scan (e.g. https://example.com).",
    )
    follow_redirects: bool = Field(
        default=True,
        description="Whether the crawler should follow HTTP redirects.",
    )
    render_js: bool = Field(
        default=True,
        description="Render JavaScript-heavy pages via a headless browser.",
    )
    max_depth: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum link-follow depth per target (0 = target page only).",
    )
    check_breaches: bool = Field(
        default=True,
        description="Query breach databases for leaked credentials.",
    )
    timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Per-page request timeout in seconds.",
    )


# ---------------------------------------------------------------------------
# Sub-models used inside the scan result
# ---------------------------------------------------------------------------

class LinkInfo(BaseModel):
    url: str
    anchor_text: str = ""
    link_type: str = Field(
        ..., description="'internal' or 'external'"
    )


class ContactInfo(BaseModel):
    emails: list[str] = Field(default_factory=list)
    phone_numbers: list[str] = Field(default_factory=list)
    social_profiles: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Aggregated findings with source-page provenance
# ---------------------------------------------------------------------------

class EmailFinding(BaseModel):
    email: str
    found_on: list[str] = Field(
        default_factory=list,
        description="Page URLs where this email was found.",
    )


class PhoneFinding(BaseModel):
    phone: str
    found_on: list[str] = Field(
        default_factory=list,
        description="Page URLs where this phone number was found.",
    )


class SocialFinding(BaseModel):
    url: str
    platform: str = Field(default="", description="Detected platform name.")
    found_on: list[str] = Field(
        default_factory=list,
        description="Page URLs where this social profile was found.",
    )


class ExternalLinkFinding(BaseModel):
    url: str
    anchor_text: str = ""
    found_on: list[str] = Field(
        default_factory=list,
        description="Page URLs where this external link was found.",
    )


class SecretFinding(BaseModel):
    """A single exposed secret detected in the page source."""

    secret_type: str = Field(
        ..., description="Category, e.g. 'aws_access_key', 'generic_password'."
    )
    matched_pattern: str = Field(
        ..., description="The regex pattern name that triggered the match."
    )
    value_preview: str = Field(
        ...,
        description="Redacted preview of the matched value (first/last 4 chars shown).",
    )
    location: str = Field(
        ..., description="Where in the page the secret was found (e.g. 'script', 'comment', 'meta')."
    )
    severity: str = Field(
        default="high",
        description="Severity level: critical, high, medium, low.",
    )


class BreachRecord(BaseModel):
    """A single breach entry from public breach databases."""

    source: str = Field(..., description="Breach database name or identifier.")
    breach_name: str = Field(default="", description="Name of the breach.")
    domain: str = Field(default="", description="Domain associated with the breach.")
    breach_date: str = Field(default="", description="Date the breach occurred.")
    data_types: list[str] = Field(
        default_factory=list,
        description="Types of data exposed (e.g. 'email', 'password').",
    )
    description: str = Field(default="", description="Breach description.")


class PageResult(BaseModel):
    """Scan results for a single crawled page."""

    url: str
    status_code: int | None = None
    title: str = ""
    meta_description: str = ""
    content_snippet: str = Field(
        default="",
        description="First 500 characters of visible page text.",
    )
    links: list[LinkInfo] = Field(default_factory=list)
    contacts: ContactInfo = Field(default_factory=ContactInfo)
    secrets: list[SecretFinding] = Field(default_factory=list)
    error: str | None = None


class DomainSummary(BaseModel):
    """Quick-glance counts for a single target."""

    pages_scanned: int = 0
    emails_found: int = 0
    phone_numbers_found: int = 0
    social_profiles_found: int = 0
    internal_links_found: int = 0
    external_links_found: int = 0
    secrets_found: int = 0
    breaches_found: int = 0


class DomainResult(BaseModel):
    """Aggregated results for a single target domain."""

    target: str
    scan_started_at: str = ""
    scan_finished_at: str = ""
    summary: DomainSummary = Field(
        default_factory=DomainSummary,
        description="Quick-glance counts before the detailed data.",
    )
    pages_scanned: int = 0
    pages: list[PageResult] = Field(default_factory=list)
    contacts: ContactInfo = Field(
        default_factory=ContactInfo,
        description="Aggregated contacts across all pages (flat list, backwards-compat).",
    )
    emails: list[EmailFinding] = Field(
        default_factory=list,
        description="Emails with the page URLs where each was found.",
    )
    phone_numbers: list[PhoneFinding] = Field(
        default_factory=list,
        description="Phone numbers with the page URLs where each was found.",
    )
    social_profiles: list[SocialFinding] = Field(
        default_factory=list,
        description="Social profiles with the page URLs where each was found.",
    )
    internal_links: list[str] = Field(default_factory=list)
    external_links: list[ExternalLinkFinding] = Field(
        default_factory=list,
        description="External links with the page URLs where each was found.",
    )
    secrets: list[SecretFinding] = Field(
        default_factory=list,
        description="Aggregated secrets across all pages.",
    )
    breaches: list[BreachRecord] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


# ---------------------------------------------------------------------------
# Top-level response
# ---------------------------------------------------------------------------

class ScanSummary(BaseModel):
    """Top-level quick-glance counts across all targets."""

    targets: int = 0
    pages_scanned: int = 0
    emails_found: int = 0
    phone_numbers_found: int = 0
    social_profiles_found: int = 0
    internal_links_found: int = 0
    external_links_found: int = 0
    secrets_found: int = 0
    breaches_found: int = 0


class ScanResponse(BaseModel):
    """Top-level JSON response returned by POST /scan."""

    scan_id: str
    status: str = Field(
        default="completed",
        description="Overall scan status: completed, partial, failed.",
    )
    started_at: str = ""
    finished_at: str = ""
    summary: ScanSummary = Field(
        default_factory=ScanSummary,
        description="Quick-glance totals across all targets.",
    )
    total_targets: int = 0
    total_pages_scanned: int = 0
    total_secrets_found: int = 0
    total_breaches_found: int = 0
    results: list[DomainResult] = Field(default_factory=list)
