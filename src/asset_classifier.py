"""Classify a scanned asset (hostname) before applying reporting rules.

Website checks (privacy policy, cookie consent, CSP/security headers) and
email-domain checks only make sense on actual websites / mail domains. A
Microsoft 365 autodiscover CNAME, a mail host, an API endpoint, or a CDN edge
must not be graded as if it were a customer website.
"""

from __future__ import annotations

from .models import AssetClassification, DomainResult

# CNAME destination fingerprints → (asset_type, provider)
_CNAME_PROVIDERS: list[tuple[str, str, str]] = [
    ("autodiscover.outlook.com", "autodiscover_service", "Microsoft 365"),
    ("outlook.com", "mail_service", "Microsoft 365"),
    ("mail.protection.outlook.com", "mail_service", "Microsoft 365"),
    ("ghs.googlehosted.com", "mail_service", "Google Workspace"),
    ("sendgrid.net", "mail_service", "SendGrid"),
    ("statuspage.io", "cloud_service", "Atlassian Statuspage"),
    ("cloudfront.net", "cdn_proxy", "Amazon CloudFront"),
    ("cloudflare.net", "cdn_proxy", "Cloudflare"),
    ("fastly.net", "cdn_proxy", "Fastly"),
    ("akamaiedge.net", "cdn_proxy", "Akamai"),
    ("azureedge.net", "cdn_proxy", "Azure Front Door"),
    ("awsglobalaccelerator.com", "cloud_service", "AWS"),
]

# Hostname-label fingerprints → (asset_type, provider-hint)
_LABEL_HINTS: list[tuple[str, str]] = [
    ("autodiscover", "autodiscover_service"),
    ("autoconfig", "autodiscover_service"),
    ("mail", "mail_service"),
    ("smtp", "mail_service"),
    ("mx", "mail_service"),
    ("imap", "mail_service"),
    ("pop", "mail_service"),
    ("webmail", "mail_service"),
    ("vpn", "vpn"),
    ("remote", "remote_access"),
    ("rdp", "remote_access"),
    ("api", "api"),
    ("cdn", "cdn_proxy"),
]

_NONSITE_TYPES = {
    "mail_service", "autodiscover_service", "api", "remote_access", "vpn",
    "cdn_proxy", "cloud_service", "redirect", "parked_domain", "inactive",
    "unresolved",
}


def _first_cname(result: DomainResult) -> str:
    dns = result.dns
    if not dns or not dns.records:
        return ""
    cnames = getattr(dns.records, "cname_records", None) or []
    return (cnames[0].target if cnames else "").lower().rstrip(".")


def _has_mx(result: DomainResult) -> bool:
    dns = result.dns
    if not dns or not dns.records:
        return False
    return bool(getattr(dns.records, "mx_records", None))


def classify_asset(result: DomainResult) -> AssetClassification:
    """Classify *result*'s host and set which check families apply."""
    hostname = (result.target or "").replace("https://", "").replace("http://", "").split("/")[0].lower()
    labels = hostname.split(".")
    leftmost = labels[0] if labels else ""
    cname = _first_cname(result)
    evidence: list[str] = []

    asset_type = "unknown"
    provider = ""

    # 1. CNAME destination is the strongest signal.
    for needle, atype, prov in _CNAME_PROVIDERS:
        if needle in cname:
            asset_type, provider = atype, prov
            evidence.append(f"CNAME -> {cname} ({prov})")
            break

    # 2. Hostname label hints.
    if asset_type == "unknown":
        for label, atype in _LABEL_HINTS:
            if leftmost == label or leftmost.startswith(label):
                asset_type = atype
                evidence.append(f"hostname label '{leftmost}' => {atype}")
                break

    # 3. Website / resolution evidence. Positive HTTP evidence (headers, pages,
    # tech, TLS) means website regardless of whether DNS was captured.
    has_web_evidence = bool(
        (result.security and result.security.headers and (
            result.security.headers.grade or result.security.headers.findings
        ))
        or getattr(result, "pages", None) and result.pages.total
        or result.technologies
        or (result.ssl and result.ssl.grade)
    )
    dns_attempted = bool(result.dns and result.dns.records)
    dns_resolved = bool(
        dns_attempted and (
            getattr(result.dns.records, "a_records", None)
            or getattr(result.dns.records, "aaaa_records", None)
        )
    ) or bool(cname)

    if asset_type == "unknown":
        if has_web_evidence:
            asset_type = "website"
        elif dns_attempted and not dns_resolved:
            # DNS was captured and nothing resolved => genuinely unresolved.
            asset_type = "unresolved"
            evidence.append("DNS captured but no A/AAAA/CNAME records resolved")
        else:
            # No DNS and no web evidence — assume website (default subject).
            asset_type = "website"

    is_site = asset_type in ("website", "web_application")
    is_mail = asset_type in ("mail_service",) or (_has_mx(result) and is_site)

    return AssetClassification(
        hostname=hostname,
        asset_type=asset_type,
        provider=provider,
        evidence=evidence or [f"classified as {asset_type}"],
        website_checks_applicable=is_site,
        privacy_checks_applicable=is_site,
        cookie_checks_applicable=is_site,
        email_domain_checks_applicable=is_mail or is_site,
    )


__all__ = ["classify_asset"]
