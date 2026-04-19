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


class ReconRequest(BaseModel):
    """Base payload for per-capability /recon/* endpoints."""

    targets: list[str] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="One or more domain URLs to probe.",
    )
    timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Per-request timeout in seconds.",
    )


class CrawlReconRequest(ReconRequest):
    """Payload for endpoints that need crawled HTML."""

    render_js: bool = Field(
        default=False,
        description="Render JavaScript-heavy pages via a headless browser.",
    )
    follow_redirects: bool = Field(
        default=True,
        description="Whether the crawler should follow HTTP redirects.",
    )
    max_depth: int = Field(
        default=0,
        ge=0,
        le=5,
        description="Link-follow depth (0 = landing page only).",
    )


class BreachReconRequest(ReconRequest):
    """Payload for /recon/breaches."""

    emails: list[str] = Field(
        default_factory=list,
        max_length=100,
        description="Optional seed emails to look up in addition to the domain.",
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
    found_on: str = Field(
        default="",
        description="Page URL where the secret was detected.",
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


# ---------------------------------------------------------------------------
# Security-hardening check models
# ---------------------------------------------------------------------------

class HeaderFinding(BaseModel):
    """Result for a single security header check."""

    header: str = Field(..., description="Header name (e.g. 'Strict-Transport-Security').")
    status: str = Field(..., description="'present', 'missing', or 'weak'.")
    value: str = Field(default="", description="Header value if present.")
    recommendation: str = Field(default="", description="What to do to fix this.")
    severity: str = Field(default="medium", description="low, medium, high, critical.")


class SecurityHeadersResult(BaseModel):
    """Aggregated security-headers audit for a target."""

    grade: str = Field(default="", description="Letter grade: A, B, C, D, F.")
    score: int = Field(default=0, description="Numeric score 0-100.")
    findings: list[HeaderFinding] = Field(default_factory=list)
    server: str = Field(default="", description="Server header value (information leakage).")
    powered_by: str = Field(default="", description="X-Powered-By value (information leakage).")


class CookieFinding(BaseModel):
    """Security audit for a single cookie."""

    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str = Field(default="", description="None, Lax, or Strict.")
    path: str = ""
    issues: list[str] = Field(default_factory=list)
    severity: str = Field(default="low")


class SSLCertResult(BaseModel):
    """TLS certificate details and issues."""

    is_valid: bool = True
    issuer: str = ""
    subject: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int = 0
    version: int = 0
    serial_number: str = ""
    signature_algorithm: str = ""
    san: list[str] = Field(default_factory=list, description="Subject Alternative Names.")
    issues: list[str] = Field(default_factory=list)
    grade: str = Field(default="", description="A, B, C, D, F based on issues found.")
    tls_version: str = Field(default="", description="Negotiated TLS version (e.g. TLSv1.3).")
    cipher: str = Field(default="", description="Negotiated cipher suite.")


class SensitivePathFinding(BaseModel):
    """An exposed sensitive path discovered on the target."""

    path: str
    url: str = ""
    status_code: int = 0
    content_length: int = 0
    risk: str = Field(default="", description="Why this path is sensitive.")
    severity: str = Field(default="high")


class IoCFinding(BaseModel):
    """An Indicator of Compromise detected on a page."""

    ioc_type: str = Field(
        ..., description="Category: cryptominer, hidden_iframe, obfuscated_js, seo_spam, "
        "credential_harvest, defacement, webshell_path, suspicious_script.",
    )
    description: str = Field(..., description="Human-readable explanation of the finding.")
    evidence: str = Field(
        default="",
        description="Truncated snippet or URL that triggered the detection.",
    )
    location: str = Field(
        default="body",
        description="Where in the page (script, body, iframe, form).",
    )
    severity: str = Field(default="high", description="critical, high, medium, low.")


# ---------------------------------------------------------------------------
# Tech fingerprint + JavaScript deep-mining models (used by /recon/* and /scan)
# ---------------------------------------------------------------------------

class TechFinding(BaseModel):
    name: str
    categories: list[str] = Field(default_factory=list)
    version: str | None = None
    confidence: str = Field(default="medium", description="high, medium, or low.")
    evidence: list[str] = Field(
        default_factory=list,
        description="List of signal sources, e.g. 'header:server', 'html:meta:generator'.",
    )


class TechIntelResult(BaseModel):
    target: str
    technologies: list[TechFinding] = Field(default_factory=list)
    error: str | None = None


class JSIntelResult(BaseModel):
    target: str
    scripts_scanned: int = 0
    api_endpoints: list[str] = Field(default_factory=list)
    internal_hosts: list[str] = Field(default_factory=list)
    sourcemaps_found: list[str] = Field(default_factory=list)
    recovered_source_files: list[str] = Field(default_factory=list)
    error: str | None = None


# ---------------------------------------------------------------------------
# Passive intel models (DNS, CT logs, RDAP, Wayback)
# ---------------------------------------------------------------------------

class MXRecord(BaseModel):
    priority: int
    host: str


class SOARecord(BaseModel):
    primary_ns: str = ""
    admin_email: str = ""
    serial: int = 0
    refresh: int = 0
    retry: int = 0
    expire: int = 0
    minimum_ttl: int = 0


class SRVRecord(BaseModel):
    service: str = ""
    priority: int = 0
    weight: int = 0
    port: int = 0
    target: str = ""


class ARecord(BaseModel):
    address: str
    ttl: int = 0
    reverse: str = Field(default="", description="Reverse DNS (PTR) hostname if available.")


class AAAARecord(BaseModel):
    address: str
    ttl: int = 0
    reverse: str = Field(default="", description="Reverse DNS (PTR) hostname if available.")


class MXRecordFull(BaseModel):
    priority: int = 0
    host: str
    ttl: int = 0


class NSRecord(BaseModel):
    host: str
    ttl: int = 0


class TXTRecord(BaseModel):
    data: str
    ttl: int = 0
    entries: list[str] = Field(default_factory=list, description="Parsed entries from the TXT record.")


class CNAMERecord(BaseModel):
    target: str
    ttl: int = 0


class CAARecord(BaseModel):
    flags: int = 0
    tag: str = ""
    value: str = ""
    ttl: int = 0


class DNSResult(BaseModel):
    domain: str
    a_records: list[ARecord] = Field(default_factory=list)
    aaaa_records: list[AAAARecord] = Field(default_factory=list)
    mx_records: list[MXRecordFull] = Field(default_factory=list)
    ns_records: list[NSRecord] = Field(default_factory=list)
    txt_records: list[TXTRecord] = Field(default_factory=list)
    cname_records: list[CNAMERecord] = Field(default_factory=list)
    soa_record: SOARecord | None = None
    srv_records: list[SRVRecord] = Field(default_factory=list)
    caa_records: list[CAARecord] = Field(default_factory=list, description="CAA records — which CAs may issue certs.")
    ptr_records: list[str] = Field(default_factory=list, description="Reverse DNS lookup results for A records.")
    dnssec: bool | None = Field(default=None, description="True if DNSSEC is enabled (DNSKEY found).")
    error: str | None = None


class SPFResult(BaseModel):
    raw: str | None = None
    exists: bool = False
    all_qualifier: str | None = Field(
        default=None,
        description="Terminal mechanism: '-all' (fail), '~all' (softfail), '+all' (pass), '?all' (neutral).",
    )
    includes: list[str] = Field(default_factory=list, description="SPF include: targets.")
    issues: list[str] = Field(default_factory=list)


class DMARCResult(BaseModel):
    raw: str | None = None
    exists: bool = False
    policy: str | None = Field(default=None, description="p= tag: none, quarantine, reject.")
    subdomain_policy: str | None = Field(default=None, description="sp= tag.")
    pct: int = Field(default=100, description="Percentage of messages subject to policy.")
    rua: list[str] = Field(default_factory=list, description="Aggregate report URIs.")
    issues: list[str] = Field(default_factory=list)


class DKIMResult(BaseModel):
    selectors_checked: list[str] = Field(default_factory=list)
    selectors_found: list[str] = Field(default_factory=list)
    issues: list[str] = Field(default_factory=list)


class EmailSecurityResult(BaseModel):
    domain: str
    spf: SPFResult = Field(default_factory=SPFResult)
    dmarc: DMARCResult = Field(default_factory=DMARCResult)
    dkim: DKIMResult = Field(default_factory=DKIMResult)
    mail_providers: list[str] = Field(
        default_factory=list,
        description="Inferred mail providers from MX records (e.g. 'Google Workspace', 'Microsoft 365').",
    )
    grade: str = Field(default="", description="A-F email security grade.")
    error: str | None = None


class ASNInfo(BaseModel):
    ip: str
    asn: int | None = None
    asn_name: str = ""
    prefix: str = ""
    country_code: str = ""
    registry: str = ""


class IPEnrichmentResult(BaseModel):
    domain: str
    records: list[ASNInfo] = Field(default_factory=list)
    hosting_providers: list[str] = Field(
        default_factory=list,
        description="Friendly names derived from ASN owners (e.g. 'AWS', 'Cloudflare').",
    )
    countries: list[str] = Field(default_factory=list)
    error: str | None = None


class CTResult(BaseModel):
    domain: str
    subdomains: list[str] = Field(
        default_factory=list,
        description="Deduped subdomains observed in CT log issuances.",
    )
    issuers: list[str] = Field(default_factory=list)
    certificates_seen: int = 0
    error: str | None = None


class RDAPResult(BaseModel):
    domain: str
    registrar: str = ""
    created: str = ""
    expires: str = ""
    name_servers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
    error: str | None = None


class WaybackResult(BaseModel):
    domain: str
    first_seen: str = ""
    last_seen: str = ""
    snapshot_count: int = 0
    recent_snapshots: list[str] = Field(default_factory=list)
    error: str | None = None


class PassiveIntelResult(BaseModel):
    """Aggregated passive intel for a single target (no traffic to target)."""

    dns: DNSResult | None = None
    ct: CTResult | None = None
    rdap: RDAPResult | None = None
    wayback: WaybackResult | None = None
    email_security: EmailSecurityResult | None = None
    ip_enrichment: IPEnrichmentResult | None = None
    breaches: list[BreachRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# FAIR (Factor Analysis of Information Risk) signals
# ---------------------------------------------------------------------------
# Maps the evidence collected by the scanner onto the FAIR risk model so a
# downstream system (e.g. Xano) can assemble a consistent risk profile.
#
# FAIR core relationships:
#   Risk               = Loss Event Frequency × Loss Magnitude
#   Loss Event Freq.   = Threat Event Freq. × Vulnerability
#   Vulnerability      = Threat Capability vs. Resistance (Control) Strength
#
# Every score is normalised 0-100 (higher = more of that factor), regardless
# of whether the factor is "bad" (TEF, Vulnerability, Loss Magnitude) or
# "good" (Control Strength). Loss Event Frequency and the composite
# overall_risk are derived from the factor scores.


class FAIRSignal(BaseModel):
    """A single piece of evidence mapped onto a FAIR factor."""

    name: str = Field(..., description="Short machine-readable identifier, e.g. 'exposed_secrets'.")
    score: int = Field(
        ..., ge=0, le=100,
        description="Normalised 0-100 score for this signal within its factor.",
    )
    weight: float = Field(
        default=1.0, ge=0.0,
        description="Relative weight of this signal when aggregating the factor.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Human-readable evidence strings that drove the score.",
    )


class FAIRFactor(BaseModel):
    """A single FAIR factor: its aggregated score and the underlying signals."""

    score: int = Field(
        default=0, ge=0, le=100,
        description="Weighted average of the signal scores below.",
    )
    signals: list[FAIRSignal] = Field(default_factory=list)
    notes: str = Field(
        default="",
        description="Free-form commentary about how this factor was derived.",
    )


class FAIRSignals(BaseModel):
    """FAIR-aligned risk signals derived from a single DomainResult."""

    threat_event_frequency: FAIRFactor = Field(
        default_factory=FAIRFactor,
        description="How often threat actors are likely to engage with this target.",
    )
    vulnerability: FAIRFactor = Field(
        default_factory=FAIRFactor,
        description="Probability that a threat engagement becomes a loss event.",
    )
    control_strength: FAIRFactor = Field(
        default_factory=FAIRFactor,
        description="Strength of observed defences (WAF, TLS, headers, cookies…).",
    )
    loss_magnitude: FAIRFactor = Field(
        default_factory=FAIRFactor,
        description="Potential impact of a loss event based on observed exposure.",
    )
    loss_event_frequency: int = Field(
        default=0, ge=0, le=100,
        description="Derived: TEF × Vulnerability, attenuated by Control Strength.",
    )
    overall_risk: int = Field(
        default=0, ge=0, le=100,
        description="Derived composite: LEF × Loss Magnitude (both normalised).",
    )
    risk_tier: str = Field(
        default="low",
        description="Banded tier: low (0-24), medium (25-49), high (50-74), critical (75-100).",
    )
    confidence: str = Field(
        default="low",
        description=(
            "How much evidence was available when scoring. 'low' for passive, "
            "'medium' for light-touch, 'high' for standard/full scans."
        ),
    )
    scan_mode: str = Field(
        default="",
        description="Which orchestrator produced these signals: passive, lighttouch, standard, full.",
    )


# ---------------------------------------------------------------------------
# EASM report layer — business-grade classification and prioritization
# ---------------------------------------------------------------------------


class FindingClassification(str, Enum):
    confirmed_issue = "confirmed_issue"
    platform_behavior = "platform_behavior"
    informational = "informational"
    false_positive_likely = "false_positive_likely"


class FindingOwner(str, Enum):
    customer = "customer"
    platform = "platform"
    third_party = "third_party"
    not_actionable = "not_actionable"


class PrioritizedFinding(BaseModel):
    id: str = Field(..., description="Stable identifier, e.g. 'missing_hsts', 'exposed_env'.")
    title: str
    category: str = Field(..., description="E.g. 'security_headers', 'ssl', 'cookies', 'secrets', 'email_security'.")
    severity: str = Field(default="medium", description="critical / high / medium / low / info.")
    classification: FindingClassification
    confidence: str = Field(default="medium", description="high / medium / low.")
    owner: FindingOwner
    platform_name: str = Field(default="", description="If owner=platform, which platform.")
    why_it_matters: str = Field(default="", description="One sentence explaining business impact.")
    business_impact: str = Field(default="", description="E.g. 'Data breach risk', 'Compliance gap'.")
    evidence: list[str] = Field(default_factory=list)
    recommended_action: str = Field(default="", description="One-line remediation guidance.")
    source_field: str = Field(default="", description="Which DomainResult field this came from.")


class SourcemapSummary(BaseModel):
    detected: bool = False
    count: int = 0
    ownership: str = Field(default="", description="'vendor', 'first_party', 'mixed', or 'unknown'.")
    proprietary_exposure: str = Field(default="none", description="'none', 'low', or 'high'.")


class JSIntelSummary(BaseModel):
    scripts_scanned: int = 0
    api_endpoints_count: int = 0
    internal_hosts_count: int = 0
    sourcemaps: SourcemapSummary = Field(default_factory=SourcemapSummary)
    notable_endpoints: list[str] = Field(
        default_factory=list, description="First-party /api/* endpoints, max 5.",
    )


class CookieSummary(BaseModel):
    total: int = 0
    with_issues: int = 0
    platform_standard: int = Field(default=0, description="Cookie issues that are expected platform behavior.")
    customer_actionable: int = 0
    notable: list[str] = Field(default_factory=list, description="Non-platform cookies with issues, by name.")


class TechSummary(BaseModel):
    platform: str = Field(default="", description="Primary platform detected (Wix, Shopify, WordPress, etc.).")
    high_confidence: list[str] = Field(default_factory=list, description="Tech names with confidence=high.")
    other_count: int = Field(default=0, description="Count of low/medium confidence detections.")


class AssetContext(BaseModel):
    """Inferred business context for the asset."""
    asset_type: str = Field(default="", description="E.g. 'brochure_site', 'ecommerce', 'web_app', 'api', 'email_only'.")
    environment: str = Field(default="", description="'production', 'staging', 'development', or 'unknown'.")
    audience: str = Field(default="", description="'customer_facing', 'internal', 'unknown'.")
    hosting_type: str = Field(default="", description="'managed_platform', 'cloud_hosted', 'self_hosted', 'unknown'.")
    business_criticality: str = Field(default="", description="'high', 'medium', 'low' — inferred from asset type and exposure.")
    inferred_from: list[str] = Field(default_factory=list, description="Evidence used for inference.")


class DNSPostureSummary(BaseModel):
    """Full DNS posture + IP/ASN enrichment for EASM report."""
    # Raw DNS records
    a_records: list[str] = Field(default_factory=list, description="IPv4 addresses.")
    aaaa_records: list[str] = Field(default_factory=list, description="IPv6 addresses.")
    a_record_count: int = 0
    has_ipv6: bool = False
    mx_hosts: list[str] = Field(default_factory=list, description="MX records as 'priority host'.")
    nameservers: list[str] = Field(default_factory=list)
    cname_chain: list[str] = Field(default_factory=list, description="CNAME records.")
    txt_records: list[str] = Field(default_factory=list, description="TXT records.")
    # SOA
    soa_primary_ns: str = ""
    soa_admin_email: str = ""
    soa_serial: int = 0
    soa_refresh: int = 0
    soa_retry: int = 0
    soa_expire: int = 0
    soa_minimum_ttl: int = 0
    # SRV / CAA / PTR / DNSSEC
    srv_services: list[str] = Field(default_factory=list, description="Discovered SRV service names.")
    caa_records: list[str] = Field(default_factory=list, description="CAA policy records.")
    caa_restricted: bool = Field(default=False, description="True if CAA restricts certificate issuance.")
    ptr_records: list[str] = Field(default_factory=list, description="Reverse DNS for A records.")
    dnssec_enabled: bool | None = Field(default=None, description="True if DNSSEC is enabled.")
    # Email security
    mail_providers: list[str] = Field(default_factory=list)
    spf_status: str = Field(default="", description="'pass', 'soft_fail', 'weak', 'not_found'.")
    dmarc_status: str = Field(default="", description="'enforce', 'monitor', 'not_found'.")
    dkim_status: str = Field(default="", description="'found', 'not_found'.")
    email_grade: str = ""
    # IP / ASN enrichment
    ip_asn_map: list[dict] = Field(default_factory=list, description="Per-IP ASN info: ip, asn, asn_name, prefix, country_code.")
    hosting_providers: list[str] = Field(default_factory=list, description="Inferred hosting providers from ASN.")
    hosting_countries: list[str] = Field(default_factory=list, description="Countries where IPs are geolocated.")


class CertificateSummary(BaseModel):
    """Certificate posture from SSL check + CT logs."""
    current_valid: bool = True
    current_issuer: str = ""
    current_grade: str = ""
    days_until_expiry: int = 0
    san_domains: list[str] = Field(default_factory=list, description="Subject Alternative Names on current cert.")
    ct_subdomains: list[str] = Field(default_factory=list, description="Subdomains seen in CT logs.")
    ct_issuers: list[str] = Field(default_factory=list, description="Unique CA issuers from CT history.")
    certificates_seen: int = 0


class CloudAsset(BaseModel):
    """A discovered cloud storage or SaaS asset."""
    asset_type: str = Field(..., description="'s3_bucket', 'azure_blob', 'gcs_bucket', 'saas_platform'.")
    identifier: str = Field(..., description="Bucket name, SaaS URL, etc.")
    source: str = Field(default="", description="Where discovered: 'html', 'js', 'dns', 'headers'.")


class PageSummary(BaseModel):
    """Condensed page crawl summary for EASM report."""
    total_pages: int = 0
    unique_routes: list[str] = Field(default_factory=list, description="Canonicalized unique paths.")
    notable_pages: list[str] = Field(default_factory=list, description="Pages with findings (secrets, IoCs).")
    unique_emails: int = 0
    unique_phones: int = 0
    unique_socials: int = 0
    external_dependencies: list[str] = Field(default_factory=list, description="Top external link domains.")


class ReconArtifact(BaseModel):
    """Low-signal discovery — standard web artifacts, not sensitive paths."""
    path: str
    status_code: int = 0
    note: str = ""


class ExecutiveSummary(BaseModel):
    risk_posture: str = Field(default="", description="Low / Moderate / High / Critical.")
    narrative: str = Field(default="", description="2-4 sentence natural-language posture assessment.")
    key_positives: list[str] = Field(default_factory=list, description="Up to 3 strengths observed.")
    key_concerns: list[str] = Field(default_factory=list, description="Up to 3 areas of concern.")
    scan_coverage: str = Field(default="", description="full / lighttouch / passive.")


class EASMReport(BaseModel):
    """Business-grade EASM report layer. Additive overlay on raw scanner output."""

    generated_at: str = ""
    scan_mode: str = ""
    executive_summary: ExecutiveSummary = Field(default_factory=ExecutiveSummary)
    asset_context: AssetContext | None = None
    dns_posture: DNSPostureSummary | None = None
    certificate_summary: CertificateSummary | None = None
    cloud_assets: list[CloudAsset] = Field(default_factory=list)
    page_summary: PageSummary | None = None
    recon_artifacts: list[ReconArtifact] = Field(default_factory=list)
    prioritized_findings: list[PrioritizedFinding] = Field(
        default_factory=list, description="Sorted by severity desc, confidence desc, actionability desc.",
    )
    total_findings: int = 0
    confirmed_issues: int = 0
    platform_behaviors: int = 0
    informational_count: int = 0
    js_intel_summary: JSIntelSummary | None = None
    cookie_summary: CookieSummary | None = None
    tech_summary: TechSummary | None = None
    platform_detected: str = Field(default="", description="Primary platform if any: 'Wix', 'Shopify', etc.")


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
    ioc_findings: list[IoCFinding] = Field(
        default_factory=list,
        description="Indicators of compromise detected on this page.",
    )
    notes: str = Field(
        default="",
        description="Informational notes, e.g. Playwright fallback warning.",
    )
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
    security_headers_grade: str = Field(default="", description="A-F grade for security headers.")
    ssl_grade: str = Field(default="", description="A-F grade for SSL/TLS certificate.")
    cookie_issues: int = Field(default=0, description="Number of cookies with security issues.")
    sensitive_paths_found: int = Field(default=0, description="Number of exposed sensitive paths.")
    ioc_findings: int = Field(default=0, description="Number of indicators of compromise detected.")
    technologies_found: int = Field(default=0, description="Number of technologies identified.")
    js_endpoints_found: int = Field(default=0, description="Number of API endpoints discovered in JS.")
    subdomains_found: int = Field(default=0, description="Subdomains observed via CT logs (passive).")
    wayback_snapshots: int = Field(default=0, description="Archive.org snapshots recorded (passive).")


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
    security_headers: SecurityHeadersResult = Field(
        default_factory=SecurityHeadersResult,
        description="Security headers audit for the landing page.",
    )
    ssl_certificate: SSLCertResult = Field(
        default_factory=SSLCertResult,
        description="TLS certificate analysis.",
    )
    cookies: list[CookieFinding] = Field(
        default_factory=list,
        description="Cookie security audit.",
    )
    sensitive_paths: list[SensitivePathFinding] = Field(
        default_factory=list,
        description="Exposed sensitive paths.",
    )
    ioc_findings: list[IoCFinding] = Field(
        default_factory=list,
        description="Aggregated indicators of compromise across all pages.",
    )
    technologies: list[TechFinding] = Field(
        default_factory=list,
        description="Technologies identified on the landing page.",
    )
    js_intel: JSIntelResult | None = Field(
        default=None,
        description="JavaScript bundle mining results (endpoints, sourcemaps, internal hosts).",
    )
    passive_intel: PassiveIntelResult | None = Field(
        default=None,
        description="Third-party-sourced intel (DNS, CT logs, RDAP, Wayback, breaches).",
    )
    fair_signals: FAIRSignals | None = Field(
        default=None,
        description=(
            "FAIR-aligned risk signals (TEF, Vulnerability, Control Strength, "
            "Loss Magnitude) derived from the evidence in this result. Use "
            "these signals to build a risk profile in a downstream system."
        ),
    )
    easm_report: EASMReport | None = Field(
        default=None,
        description=(
            "Business-grade EASM report with classified findings, executive "
            "summary, and prioritization. Generated as a post-processing "
            "step over the raw scanner output."
        ),
    )
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
    total_cookie_issues: int = 0
    total_sensitive_paths: int = 0
    total_ioc_findings: int = 0


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


# ---------------------------------------------------------------------------
# Per-capability (/recon/*) response models
# ---------------------------------------------------------------------------

class SSLReconResult(BaseModel):
    target: str
    ssl: SSLCertResult = Field(default_factory=SSLCertResult)
    error: str | None = None


class HeadersReconResult(BaseModel):
    target: str
    headers: SecurityHeadersResult = Field(default_factory=SecurityHeadersResult)
    error: str | None = None


class CookiesReconResult(BaseModel):
    target: str
    cookies: list[CookieFinding] = Field(default_factory=list)
    error: str | None = None


class PathsReconResult(BaseModel):
    target: str
    sensitive_paths: list[SensitivePathFinding] = Field(default_factory=list)
    error: str | None = None


class CrawlReconResult(BaseModel):
    target: str
    pages_scanned: int = 0
    pages: list[PageResult] = Field(default_factory=list)
    error: str | None = None


class ContactReconResult(BaseModel):
    target: str
    emails: list[EmailFinding] = Field(default_factory=list)
    phone_numbers: list[PhoneFinding] = Field(default_factory=list)
    social_profiles: list[SocialFinding] = Field(default_factory=list)
    error: str | None = None


class LinkReconResult(BaseModel):
    target: str
    internal_links: list[str] = Field(default_factory=list)
    external_links: list[ExternalLinkFinding] = Field(default_factory=list)
    error: str | None = None


class SecretsReconResult(BaseModel):
    target: str
    secrets: list[SecretFinding] = Field(default_factory=list)
    error: str | None = None


class IoCReconResult(BaseModel):
    target: str
    ioc_findings: list[IoCFinding] = Field(default_factory=list)
    error: str | None = None


class BreachReconResult(BaseModel):
    target: str
    breaches: list[BreachRecord] = Field(default_factory=list)
    error: str | None = None


