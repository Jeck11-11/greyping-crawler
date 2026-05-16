"""Data models for the OSINT reconnaissance API."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, HttpUrl, model_validator


def _fingerprint(*parts: str) -> str:
    """Produce a stable 16-char hex fingerprint for finding deduplication."""
    raw = "|".join(str(p) for p in parts)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


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


class EmailValidationRequest(BaseModel):
    """Payload for /recon/email-validation."""

    emails: list[str] = Field(
        ...,
        min_length=1,
        max_length=20,
        description="One or more email addresses to validate.",
    )
    timeout: int = Field(
        default=30,
        ge=5,
        le=120,
        description="Per-request timeout in seconds.",
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
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> SecretFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("secret", self.secret_type, self.found_on, self.value_preview)
        return self


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
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> BreachRecord:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("breach", self.breach_name, self.domain)
        return self


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
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> HeaderFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("header", self.header, self.status)
        return self


class CORSAnalysis(BaseModel):
    """Detailed CORS policy analysis extracted from Access-Control-* headers."""

    origin_policy: str = Field(default="", description="Access-Control-Allow-Origin value.")
    allows_credentials: bool = False
    allowed_methods: list[str] = Field(default_factory=list)
    allowed_headers: list[str] = Field(default_factory=list)
    exposed_headers: list[str] = Field(default_factory=list)
    max_age: int | None = None
    null_origin: bool = False
    issues: list[str] = Field(default_factory=list)


class SecurityHeadersResult(BaseModel):
    """Aggregated security-headers audit for a target."""

    grade: str = Field(default="", description="Letter grade: A, B, C, D, F.")
    score: int = Field(default=0, description="Numeric score 0-100.")
    findings: list[HeaderFinding] = Field(default_factory=list)
    server: str = Field(default="", description="Server header value (information leakage).")
    powered_by: str = Field(default="", description="X-Powered-By value (information leakage).")
    cors: CORSAnalysis = Field(default_factory=CORSAnalysis, description="Detailed CORS policy analysis.")


class CookieFinding(BaseModel):
    """Security audit for a single cookie."""

    name: str
    secure: bool = False
    http_only: bool = False
    same_site: str = Field(default="", description="None, Lax, or Strict.")
    path: str = ""
    issues: list[str] = Field(default_factory=list)
    severity: str = Field(default="low")
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> CookieFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("cookie", self.name, ":".join(sorted(self.issues)))
        return self


class SSLCertResult(BaseModel):
    """TLS certificate details and issues."""

    host: str = ""
    resolved_ip: str = ""
    issued_to: str = ""
    issued_o: str = ""
    issuer_c: str = ""
    issuer_o: str = ""
    issuer_ou: str = ""
    issuer_cn: str = ""
    cert_sn: str = ""
    cert_sha1: str = ""
    cert_alg: str = ""
    cert_ver: int = 0
    cert_sans: list[str] = Field(default_factory=list)
    cert_exp: bool = False
    cert_valid: bool = True
    valid_from: str = ""
    valid_till: str = ""
    validity_days: int = 0
    days_left: int = 0
    valid_days_to_expire: int = 0
    hsts_header_enabled: bool = False
    is_self_signed: bool = False
    is_wildcard: bool = False
    final_url: str = ""
    grade: str = Field(default="")
    tls_version: str = Field(default="")
    cipher: str = Field(default="")
    cipher_bits: int = Field(default=0, description="Negotiated cipher key exchange bit length.")
    cipher_strength: str = Field(default="", description="strong (256+), acceptable (128), weak (<128).")
    pfs: bool = Field(default=False, description="True if cipher uses ephemeral key exchange (ECDHE/DHE).")
    key_type: str = Field(default="", description="Public key type: RSA, EC, DSA, Ed25519, Ed448.")
    key_size: int = Field(default=0, description="Public key size in bits (e.g. 2048, 256).")
    ocsp_must_staple: bool = Field(default=False, description="True if cert has OCSP Must-Staple extension.")
    ocsp_responder: str = Field(default="", description="OCSP responder URL from AIA extension.")
    ca_issuers_url: str = Field(default="", description="CA Issuers URL from AIA extension.")
    has_sct: bool = Field(default=False, description="True if cert has embedded Signed Certificate Timestamps.")
    issues: list[str] = Field(default_factory=list)


class SensitivePathFinding(BaseModel):
    """An exposed sensitive path discovered on the target."""

    path: str
    url: str = ""
    status_code: int = 0
    content_length: int = 0
    risk: str = Field(default="", description="Why this path is sensitive.")
    severity: str = Field(default="high")
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> SensitivePathFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("path", self.path, str(self.status_code))
        return self


class RobotsTxtResult(BaseModel):
    """Parsed robots.txt intelligence."""

    found: bool = False
    disallow_rules: list[str] = Field(default_factory=list)
    sitemap_urls: list[str] = Field(default_factory=list)
    crawl_delay: int | None = None
    raw_snippet: str = Field(default="", description="First 2000 chars of raw content.")


class SitemapResult(BaseModel):
    """Parsed sitemap.xml intelligence."""

    found: bool = False
    url_count: int = 0
    urls: list[str] = Field(default_factory=list, description="Up to 100 URLs.")
    nested_sitemaps: list[str] = Field(default_factory=list)


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
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> IoCFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("ioc", self.ioc_type, self.evidence[:100])
        return self


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


class ThirdPartyResource(BaseModel):
    url: str = ""
    resource_type: str = Field(default="", description="script or stylesheet.")
    provider: str = Field(default="unknown", description="CDN provider name or 'unknown'.")
    library: str = Field(default="", description="Detected library name or empty.")
    version: str = Field(default="", description="Extracted version or empty.")
    has_sri: bool = Field(default=False, description="True if integrity= attribute present.")
    risk: str = Field(default="info", description="high, medium, low, or info.")
    issues: list[str] = Field(default_factory=list)


class SupplyChainResult(BaseModel):
    total_external_resources: int = 0
    scripts_without_sri: int = 0
    stylesheets_without_sri: int = 0
    vulnerable_libraries: int = 0
    providers: list[str] = Field(default_factory=list, description="Unique CDN/hosting providers.")
    resources: list[ThirdPartyResource] = Field(default_factory=list)
    risk_summary: str = Field(default="none", description="Overall risk: high, medium, low, none.")
    issues: list[str] = Field(default_factory=list)


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


class TLSARecord(BaseModel):
    usage: int = Field(0, description="Certificate usage: 0=CA, 1=EE, 2=Trust anchor, 3=Domain-issued.")
    selector: int = Field(0, description="Selector: 0=full cert, 1=SubjectPublicKeyInfo.")
    matching_type: int = Field(0, description="Matching type: 0=exact, 1=SHA-256, 2=SHA-512.")
    certificate_data: str = Field("", description="Hex-encoded certificate association data.")
    port: int = Field(0, description="Port from the TLSA query name (e.g. 25, 443).")
    protocol: str = Field("tcp", description="Protocol from the TLSA query name.")
    ttl: int = 0


class SSHFPRecord(BaseModel):
    algorithm: int = Field(0, description="Key algorithm: 1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519.")
    fingerprint_type: int = Field(0, description="Hash type: 1=SHA-1, 2=SHA-256.")
    fingerprint: str = Field("", description="Hex-encoded key fingerprint.")
    ttl: int = 0


class DSRecord(BaseModel):
    key_tag: int = 0
    algorithm: int = Field(0, description="DNSSEC algorithm number.")
    digest_type: int = Field(0, description="Digest type: 1=SHA-1, 2=SHA-256, 4=SHA-384.")
    digest: str = Field("", description="Hex-encoded digest.")
    ttl: int = 0


class NAPTRRecord(BaseModel):
    order: int = 0
    preference: int = 0
    flags: str = Field("", description="NAPTR flags (e.g. 'S', 'A', 'U').")
    service: str = Field("", description="Service field (e.g. 'SIP+D2U', 'E2U+sip').")
    regexp: str = Field("", description="Regular expression for URI rewriting.")
    replacement: str = Field("", description="Replacement domain name.")
    ttl: int = 0


class LOCRecord(BaseModel):
    latitude: float = Field(0.0, description="Latitude in decimal degrees.")
    longitude: float = Field(0.0, description="Longitude in decimal degrees.")
    altitude: float = Field(0.0, description="Altitude in meters above sea level.")
    size: float = Field(0.0, description="Diameter of sphere enclosing the location (meters).")
    horizontal_precision: float = Field(0.0, description="Horizontal precision (meters).")
    vertical_precision: float = Field(0.0, description="Vertical precision (meters).")
    ttl: int = 0


class RPRecord(BaseModel):
    mbox: str = Field("", description="Email address of responsible person (encoded as DNS name).")
    txt_domain: str = Field("", description="Domain name with TXT record containing additional info.")
    ttl: int = 0


class HINFORecord(BaseModel):
    cpu: str = Field("", description="CPU type string.")
    os: str = Field("", description="Operating system string.")
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
    tlsa_records: list[TLSARecord] = Field(default_factory=list, description="DANE/TLSA certificate association records.")
    sshfp_records: list[SSHFPRecord] = Field(default_factory=list, description="SSH key fingerprints published in DNS.")
    ds_records: list[DSRecord] = Field(default_factory=list, description="DNSSEC delegation signer records.")
    naptr_records: list[NAPTRRecord] = Field(default_factory=list, description="Naming authority pointer records (SIP/VoIP).")
    loc_records: list[LOCRecord] = Field(default_factory=list, description="Geographic location records.")
    rp_records: list[RPRecord] = Field(default_factory=list, description="Responsible person records.")
    hinfo_records: list[HINFORecord] = Field(default_factory=list, description="Host information records (CPU/OS).")
    error: str | None = None


class SPFMechanism(BaseModel):
    """A single parsed SPF mechanism (ip4, ip6, a, mx, include, redirect, etc.)."""
    qualifier: str = Field(default="+", description="'+' pass, '-' fail, '~' softfail, '?' neutral.")
    mechanism: str = Field(..., description="Mechanism type: ip4, ip6, a, mx, include, redirect, all, etc.")
    value: str = Field(default="", description="Mechanism value (IP, CIDR, domain).")


class SPFIncludeNode(BaseModel):
    """One node in the SPF include resolution tree."""
    domain: str
    raw_record: str | None = None
    service: str = Field(default="", description="Mapped service name, e.g. 'Google Workspace'.")
    ip4_ranges: list[str] = Field(default_factory=list)
    ip6_ranges: list[str] = Field(default_factory=list)
    children: list[SPFIncludeNode] = Field(default_factory=list)
    error: str | None = None


class SPFSenderInfo(BaseModel):
    """An IP address extracted from SPF with ASN enrichment."""
    ip: str
    source: str = Field(default="", description="Which SPF mechanism/include produced this IP.")
    asn: int | None = None
    asn_name: str = ""
    prefix: str = ""
    country_code: str = ""
    provider: str = ""


class SPFIntelResult(BaseModel):
    """Full SPF intelligence: mechanisms, include tree, resolved IPs, enrichment."""
    domain: str
    mechanisms: list[SPFMechanism] = Field(default_factory=list)
    include_tree: list[SPFIncludeNode] = Field(default_factory=list)
    ip4_ranges: list[str] = Field(default_factory=list, description="All ip4 CIDRs/addresses from SPF chain.")
    ip6_ranges: list[str] = Field(default_factory=list, description="All ip6 CIDRs/addresses from SPF chain.")
    senders: list[SPFSenderInfo] = Field(default_factory=list, description="Enriched sender IPs (ASN/org/country).")
    services_detected: list[str] = Field(default_factory=list, description="Mapped third-party services from includes.")
    dns_lookup_count: int = Field(default=0, description="Total DNS lookups in SPF chain (RFC 7208 limit: 10).")
    exceeds_lookup_limit: bool = Field(default=False, description="True if >10 DNS lookups required.")
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
    intel: SPFIntelResult | None = Field(default=None, description="Deep SPF enumeration results.")


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


class MTASTSResult(BaseModel):
    raw: str | None = None
    exists: bool = False
    version: str = Field(default="", description="MTA-STS version (e.g. 'STSv1').")
    sts_id: str = Field(default="", description="MTA-STS policy ID.")
    issues: list[str] = Field(default_factory=list)


class BIMIResult(BaseModel):
    raw: str | None = None
    exists: bool = False
    version: str = Field(default="", description="BIMI version (e.g. 'BIMI1').")
    logo_url: str = Field(default="", description="URL to the brand logo SVG (l= tag).")
    authority_url: str = Field(default="", description="URL to the VMC certificate (a= tag).")
    issues: list[str] = Field(default_factory=list)


class EmailSecurityResult(BaseModel):
    domain: str
    spf: SPFResult = Field(default_factory=SPFResult)
    dmarc: DMARCResult = Field(default_factory=DMARCResult)
    dkim: DKIMResult = Field(default_factory=DKIMResult)
    mta_sts: MTASTSResult = Field(default_factory=MTASTSResult)
    bimi: BIMIResult = Field(default_factory=BIMIResult)
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


class SubdomainEntry(BaseModel):
    """A discovered subdomain with optional IP and CDN metadata."""
    subdomain: str
    ip: str | None = None
    cloudflare: bool | None = None


class CTResult(BaseModel):
    domain: str
    subdomains: list[str] = Field(
        default_factory=list,
        description="Deduped subdomains observed in CT log issuances.",
    )
    subdomain_details: list[SubdomainEntry] = Field(
        default_factory=list,
        description="Subdomains with IP and CDN metadata from C99.",
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
    compliance: list[str] = Field(
        default_factory=list,
        description="Applicable compliance framework references.",
    )
    source_field: str = Field(default="", description="Which DomainResult field this came from.")
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> PrioritizedFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("easm", self.id)
        return self


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
        default_factory=list,
        description="Notable endpoints (/api, /graphql, /webhook, /admin, /health, /.well-known), max 10.",
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
    days_left: int = 0
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
    cloud_assets: list[CloudAsset] = Field(default_factory=list)
    recon_artifacts: list[ReconArtifact] = Field(default_factory=list)
    prioritized_findings: list[PrioritizedFinding] = Field(
        default_factory=list, description="Sorted by severity desc, confidence desc, actionability desc.",
    )
    total_findings: int = 0
    confirmed_issues: int = 0
    platform_behaviors: int = 0
    informational_count: int = 0
    compliance_summary: dict[str, int] = Field(
        default_factory=dict,
        description="Count of findings per compliance framework.",
    )
    platform_detected: str = Field(default="", description="Primary platform if any: 'Wix', 'Shopify', etc.")


class PageResult(BaseModel):
    """Scan results for a single crawled page."""

    url: str
    status_code: int | None = None
    redirect_chain: list[str] = Field(default_factory=list)
    title: str = ""
    meta_description: str = ""
    content_snippet: str = Field(
        default="",
        description="First 500 characters of visible page text.",
    )
    links: list[LinkInfo] = Field(default_factory=list, exclude=True)
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


# ---------------------------------------------------------------------------
# Nuclei / CVE / Favicon models
# ---------------------------------------------------------------------------

class NucleiFinding(BaseModel):
    template_id: str = ""
    name: str = ""
    severity: str = Field(default="", description="info, low, medium, high, critical")
    type: str = ""
    matched_at: str = ""
    description: str = ""
    reference: list[str] = Field(default_factory=list)
    extracted_results: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> NucleiFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("nuclei", self.template_id, self.matched_at)
        return self


class NucleiResult(BaseModel):
    target: str
    findings: list[NucleiFinding] = Field(default_factory=list)
    templates_run: int = 0
    scan_duration_seconds: float = 0
    error: str = ""


# ---------------------------------------------------------------------------
# ProjectDiscovery tool intermediate models
# ---------------------------------------------------------------------------

class HttpxProbeResult(BaseModel):
    """Raw result from a ProjectDiscovery httpx probe."""
    url: str = ""
    status_code: int | None = None
    title: str = ""
    content_type: str = ""
    content_length: int = 0
    technologies: list[str] = Field(default_factory=list)
    webserver: str = ""
    response_time: str = ""
    host: str = ""
    scheme: str = ""
    final_url: str = ""
    body: str = ""


class KatanaEndpoint(BaseModel):
    """A single endpoint discovered by katana."""
    url: str
    method: str = "GET"
    source: str = ""
    tag: str = ""
    body: str = ""


class KatanaCrawlResult(BaseModel):
    target: str
    endpoints: list[KatanaEndpoint] = Field(default_factory=list)
    error: str | None = None



class CVEFinding(BaseModel):
    cve_id: str
    description: str = ""
    severity: str = Field(default="", description="LOW, MEDIUM, HIGH, CRITICAL")
    cvss_score: float | None = None
    affected_tech: str = ""
    affected_version: str = ""
    reference_url: str = ""
    epss_score: float | None = Field(default=None, description="EPSS probability 0.0-1.0")
    epss_percentile: float | None = Field(default=None, description="EPSS percentile 0.0-1.0")
    in_kev: bool = Field(default=False, description="In CISA Known Exploited Vulnerabilities catalog")
    kev_due_date: str = Field(default="", description="CISA KEV remediation due date")
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> CVEFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("cve", self.cve_id, self.affected_tech)
        return self


class FaviconResult(BaseModel):
    url: str = ""
    hash: int | None = Field(default=None, description="MurmurHash3 (Shodan-compatible)")
    size_bytes: int = 0
    error: str = ""


class SubdomainTakeoverFinding(BaseModel):
    subdomain: str
    cname_target: str
    vulnerable_service: str
    status: str = Field(description="vulnerable, likely_vulnerable, service_detected")
    severity: str = Field(description="critical, high, medium, low, info")
    evidence: list[str] = Field(default_factory=list)
    remediation: str = ""
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> SubdomainTakeoverFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("takeover", self.subdomain, self.vulnerable_service)
        return self


class SubdomainEnumResult(BaseModel):
    domain: str
    live_subdomains: list[str] = Field(default_factory=list)
    sources: dict[str, int] = Field(default_factory=dict)
    error: str | None = None


class SubdomainTakeoverResult(BaseModel):
    domain: str
    enumeration: SubdomainEnumResult = Field(default_factory=lambda: SubdomainEnumResult(domain=""))
    findings: list[SubdomainTakeoverFinding] = Field(default_factory=list)
    subdomains_checked: int = 0
    scan_duration_seconds: float = 0
    error: str | None = None


class TyposquatCandidate(BaseModel):
    domain: str
    a_records: list[str] = Field(default_factory=list)
    technique: str = ""
    similarity_score: float = 0.0
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> TyposquatCandidate:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("typosquat", self.domain)
        return self


class TyposquattingResult(BaseModel):
    domain: str
    candidates_checked: int = 0
    registered_candidates: list[TyposquatCandidate] = Field(default_factory=list)
    scan_duration_seconds: float = 0
    error: str | None = None


class PrivacyIndicator(BaseModel):
    name: str
    present: bool = False
    evidence: list[str] = Field(default_factory=list)
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> PrivacyIndicator:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("privacy", self.name, str(self.present))
        return self


class PrivacyComplianceResult(BaseModel):
    domain: str
    score: int = 0
    grade: str = ""
    indicators: list[PrivacyIndicator] = Field(default_factory=list)
    consent_tool: str = ""
    error: str | None = None


class IPReputationResult(BaseModel):
    ip: str
    malicious: bool = False
    detections: list[str] = Field(default_factory=list)
    error: str | None = None


class URLReputationResult(BaseModel):
    url: str
    blacklisted: bool = False
    detections: list[str] = Field(default_factory=list)
    sources_checked: int = 0
    error: str | None = None


class EmailValidationResult(BaseModel):
    email: str
    valid: bool | None = None
    disposable: bool = False
    role_account: bool = False
    free_provider: bool = False
    error: str | None = None


class WAFResult(BaseModel):
    """WAF / firewall detection result from C99 API."""
    url: str = ""
    detected: bool = False
    firewall: str | None = None
    confidence: str = "high"
    error: str | None = None


class OpenPort(BaseModel):
    port: int
    service: str = ""
    banner: str = ""
    is_risky: bool = False
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> OpenPort:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("port", str(self.port), self.service)
        return self


class PortScanResult(BaseModel):
    target: str
    ip: str = ""
    open_ports: list[OpenPort] = Field(default_factory=list)
    ports_scanned: int = 0
    scan_duration_seconds: float = 0
    error: str | None = None


class ScreenshotResult(BaseModel):
    url: str
    image_base64: str = ""
    width: int = 0
    height: int = 0
    size_bytes: int = 0
    error: str | None = None


class CloudAssetFinding(BaseModel):
    bucket_name: str
    provider: str = ""
    url: str = ""
    status: str = ""  # "public", "exists_private"
    evidence: list[str] = Field(default_factory=list)
    severity: str = "critical"
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> CloudAssetFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("cloud", self.provider, self.bucket_name, self.status)
        return self


class CloudServiceFinding(BaseModel):
    """A cloud service detected via DNS records."""
    service: str = Field(..., description="e.g. 'aws_cloudfront', 'azure_app_service', 'aws_rds'")
    provider: str = Field(..., description="e.g. 'aws', 'azure', 'gcp'")
    record_type: str = Field(default="CNAME", description="DNS record type where found")
    record_value: str = Field(default="", description="The actual DNS record value")
    is_database: bool = Field(default=False)
    severity: str = Field(default="info")
    fingerprint: str = Field(default="")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> CloudServiceFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("cloudsvc", self.service, self.record_value)
        return self


class CloudAssetResult(BaseModel):
    domain: str
    findings: list[CloudAssetFinding] = Field(default_factory=list)
    cloud_services: list[CloudServiceFinding] = Field(default_factory=list)
    buckets_checked: int = 0
    scan_duration_seconds: float = 0
    error: str | None = None


class GitHubSecretFinding(BaseModel):
    query: str = Field(default="", description="Dork query category that matched.")
    repository: str = Field(default="", description="GitHub owner/repo.")
    file_path: str = Field(default="", description="Path within the repository.")
    file_url: str = Field(default="", description="GitHub URL to the file.")
    code_snippet: str = Field(default="", description="Redacted code fragment.")
    last_modified: str = Field(default="", description="Repository last push date.")
    severity: str = "high"
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> GitHubSecretFinding:
        if not self.fingerprint:
            self.fingerprint = _fingerprint("github", self.repository, self.file_path, self.query)
        return self


class GitHubSecretResult(BaseModel):
    domain: str
    findings: list[GitHubSecretFinding] = Field(default_factory=list)
    queries_run: int = 0
    total_matches: int = 0
    scan_duration_seconds: float = 0
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
    robots_disallow_count: int = Field(default=0, description="Disallow rules in robots.txt.")
    sitemap_url_count: int = Field(default=0, description="URLs found in sitemap.xml.")
    nuclei_findings: int = Field(default=0, description="Nuclei vulnerability findings.")
    cve_count: int = Field(default=0, description="CVEs correlated from detected tech versions.")
    favicon_hash: int | None = Field(default=None, description="Favicon mmh3 hash (Shodan pivot).")
    takeover_findings: int = Field(default=0, description="Subdomain takeover vulnerabilities found.")
    ip_malicious: bool = Field(default=False, description="Whether the target IP is flagged as malicious.")
    url_blacklisted: bool = Field(default=False, description="Whether the target URL is blacklisted.")
    emails_validated: int = Field(default=0, description="Number of discovered emails validated.")
    open_ports: int = 0
    risky_ports: int = 0
    cloud_buckets_found: int = 0
    cloud_services_found: int = 0
    exposed_databases_found: int = 0
    spf_senders_found: int = Field(default=0, description="Unique IPs/CIDRs in SPF chain.")
    spf_services_found: int = Field(default=0, description="Third-party services identified in SPF includes.")
    vulnerable_libraries: int = Field(default=0, description="Known vulnerable third-party libraries detected.")
    scripts_without_sri: int = Field(default=0, description="External scripts missing Subresource Integrity.")
    screenshots_taken: int = 0
    typosquat_candidates: int = Field(default=0, description="Registered lookalike domains found.")
    waf_detected: str = Field(default="", description="WAF/firewall product detected by C99 (empty if none).")
    privacy_score: int = Field(default=0, description="Privacy compliance score (0-100).")
    consent_tool: str = Field(default="", description="Detected cookie consent management tool.")


# ---------------------------------------------------------------------------
# Grouping models — logical sections inside DomainResult
# ---------------------------------------------------------------------------

class DNSGroup(BaseModel):
    """DNS records, email security, and IP enrichment."""
    records: DNSResult | None = None
    email_security: EmailSecurityResult | None = None
    ip_enrichment: IPEnrichmentResult | None = None


class SecurityGroup(BaseModel):
    """Security posture: headers, cookies, paths, secrets, IoCs."""
    headers: SecurityHeadersResult = Field(default_factory=SecurityHeadersResult)
    cookies: list[CookieFinding] = Field(default_factory=list)
    sensitive_paths: list[SensitivePathFinding] = Field(default_factory=list)
    secrets: list[SecretFinding] = Field(default_factory=list)
    ioc_findings: list[IoCFinding] = Field(default_factory=list)


class ContactsGroup(BaseModel):
    """Contacts with provenance."""
    emails: list[EmailFinding] = Field(default_factory=list)
    phone_numbers: list[PhoneFinding] = Field(default_factory=list)
    social_profiles: list[SocialFinding] = Field(default_factory=list)


class LinksGroup(BaseModel):
    """Internal and external links."""
    internal: list[str] = Field(default_factory=list)
    external: list[ExternalLinkFinding] = Field(default_factory=list)


class PagesSummary(BaseModel):
    """Condensed page crawl summary (replaces full page list in JSON)."""
    total: int = 0
    notable: list[str] = Field(default_factory=list, description="Admin panels, error pages, pages with findings.")
    routes: list[str] = Field(default_factory=list, description="Unique URL paths crawled.")


class PassiveIntelSlim(BaseModel):
    """Passive intel remaining after DNS/email/IP moved to dns group."""
    ct: CTResult | None = None
    rdap: RDAPResult | None = None
    wayback: WaybackResult | None = None


class VulnerabilitiesGroup(BaseModel):
    """Vulnerability scan results."""
    nuclei: NucleiResult | None = None
    cve_findings: list[CVEFinding] = Field(default_factory=list)
    subdomain_takeover: SubdomainTakeoverResult | None = None


class ReputationGroup(BaseModel):
    """IP and URL reputation checks."""
    ip: IPReputationResult | None = None
    url: URLReputationResult | None = None


class AttackStep(BaseModel):
    finding_type: str = ""
    description: str = ""
    fingerprint: str = ""


class AttackPath(BaseModel):
    title: str = ""
    severity: str = ""
    impact: str = ""
    steps: list[AttackStep] = Field(default_factory=list)
    likelihood: str = ""
    remediation: str = ""
    fingerprint: str = Field(default="", description="Stable hash for cross-scan deduplication.")

    @model_validator(mode="after")
    def _set_fingerprint(self) -> AttackPath:
        if not self.fingerprint:
            step_fps = ":".join(s.fingerprint for s in self.steps)
            self.fingerprint = _fingerprint("attack_path", self.title, step_fps)
        return self


class AttackPathResult(BaseModel):
    paths: list[AttackPath] = Field(default_factory=list)
    chains_evaluated: int = 0


class RiskAssessmentGroup(BaseModel):
    """Risk scoring and EASM report."""
    fair_signals: FAIRSignals | None = None
    easm_report: EASMReport | None = None


class DomainResult(BaseModel):
    """Aggregated results for a single target domain."""

    target: str
    scan_started_at: str = ""
    scan_finished_at: str = ""
    error: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    summary: DomainSummary = Field(default_factory=DomainSummary)

    ssl: SSLCertResult = Field(default_factory=SSLCertResult)
    dns: DNSGroup | None = None
    security: SecurityGroup = Field(default_factory=SecurityGroup)
    contacts: ContactsGroup = Field(default_factory=ContactsGroup)
    links: LinksGroup = Field(default_factory=LinksGroup)
    pages: PagesSummary = Field(default_factory=PagesSummary)
    technologies: list[TechFinding] = Field(default_factory=list)
    breaches: list[BreachRecord] = Field(default_factory=list)
    js_intel: JSIntelResult | None = None
    supply_chain: SupplyChainResult | None = None
    port_scan: PortScanResult | None = None
    cloud_assets: CloudAssetResult | None = None
    passive_intel: PassiveIntelSlim | None = None
    vulnerabilities: VulnerabilitiesGroup | None = None
    reputation: ReputationGroup | None = None
    waf: WAFResult | None = None
    typosquatting: TyposquattingResult | None = None
    privacy: PrivacyComplianceResult | None = None
    email_validations: list[EmailValidationResult] = Field(default_factory=list)
    screenshots: list[ScreenshotResult] = Field(default_factory=list)
    favicon: FaviconResult | None = None
    robots_txt: RobotsTxtResult | None = None
    sitemap: SitemapResult | None = None
    attack_paths: AttackPathResult | None = None
    risk_assessment: RiskAssessmentGroup | None = None

    # --- Backward-compat read-only properties (not serialized to JSON) ---

    @property
    def ssl_certificate(self) -> SSLCertResult:
        return self.ssl

    @property
    def security_headers(self) -> SecurityHeadersResult:
        return self.security.headers

    @property
    def cookies(self) -> list[CookieFinding]:
        return self.security.cookies

    @property
    def sensitive_paths(self) -> list[SensitivePathFinding]:
        return self.security.sensitive_paths

    @property
    def secrets(self) -> list[SecretFinding]:
        return self.security.secrets

    @property
    def ioc_findings(self) -> list[IoCFinding]:
        return self.security.ioc_findings

    @property
    def emails(self) -> list[EmailFinding]:
        return self.contacts.emails

    @property
    def phone_numbers(self) -> list[PhoneFinding]:
        return self.contacts.phone_numbers

    @property
    def social_profiles(self) -> list[SocialFinding]:
        return self.contacts.social_profiles

    @property
    def internal_links(self) -> list[str]:
        return self.links.internal

    @property
    def external_links(self) -> list[ExternalLinkFinding]:
        return self.links.external

    @property
    def pages_scanned(self) -> int:
        return self.pages.total

    @property
    def nuclei(self) -> NucleiResult | None:
        return self.vulnerabilities.nuclei if self.vulnerabilities else None

    @property
    def cve_findings(self) -> list[CVEFinding]:
        return self.vulnerabilities.cve_findings if self.vulnerabilities else []

    @property
    def subdomain_takeover(self) -> SubdomainTakeoverResult | None:
        return self.vulnerabilities.subdomain_takeover if self.vulnerabilities else None

    @property
    def ip_reputation(self) -> IPReputationResult | None:
        return self.reputation.ip if self.reputation else None

    @property
    def url_reputation(self) -> URLReputationResult | None:
        return self.reputation.url if self.reputation else None

    @property
    def fair_signals(self) -> FAIRSignals | None:
        return self.risk_assessment.fair_signals if self.risk_assessment else None

    @property
    def easm_report(self) -> EASMReport | None:
        return self.risk_assessment.easm_report if self.risk_assessment else None


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
    results: list[DomainResult] = Field(default_factory=list)
    scanner_version: str = Field(default="1.4.0", description="Scanner version for change attribution.")


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


class GitHubSecretsReconResult(BaseModel):
    target: str
    github_secrets: GitHubSecretResult | None = None
    error: str | None = None


