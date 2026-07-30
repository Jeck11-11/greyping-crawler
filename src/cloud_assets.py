"""Cloud asset discovery — bucket enumeration and DNS-based cloud service detection."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from .config import HTTP_TIMEOUT
from .models import CloudAssetFinding, CloudAssetResult, CloudServiceFinding

logger = logging.getLogger(__name__)

_BUCKET_SUFFIXES = [
    "", "-assets", "-backup", "-backups", "-media", "-static",
    "-uploads", "-data", "-files", "-dev", "-staging", "-prod",
    "-public", "-private", "-cdn", "-images", "-docs", "-logs",
]

_PROVIDERS = {
    "aws_s3": {
        "url_template": "https://{bucket}.s3.amazonaws.com/",
        "not_found": ["NoSuchBucket", "The specified bucket does not exist"],
        "private": ["AccessDenied", "AllAccessDisabled"],
        "public": ["ListBucketResult"],
    },
    "azure_blob": {
        "url_template": "https://{bucket}.blob.core.windows.net/?comp=list",
        "not_found": ["BlobNotFound", "ContainerNotFound", "The specified container does not exist", "OutOfRangeInput"],
        "private": ["AuthenticationFailed", "AuthorizationFailure", "Server failed to authenticate"],
        "public": ["EnumerationResults"],
    },
    "gcs": {
        "url_template": "https://storage.googleapis.com/{bucket}/",
        "not_found": ["NoSuchBucket", "The specified bucket does not exist", "Not Found"],
        "private": ["AccessDenied", "Access denied"],
        "public": ["ListBucketResult", "<Contents>"],
    },
    "digitalocean_spaces": {
        "url_template": "https://{bucket}.nyc3.digitaloceanspaces.com/",
        "not_found": ["NoSuchBucket", "The specified bucket does not exist"],
        "private": ["AccessDenied"],
        "public": ["ListBucketResult"],
    },
    "backblaze_b2": {
        "url_template": "https://{bucket}.s3.us-west-004.backblazeb2.com/",
        "not_found": ["NoSuchBucket", "NoSuchKey", "The specified bucket does not exist"],
        "private": ["AccessDenied"],
        "public": ["ListBucketResult"],
    },
    "alibaba_oss": {
        "url_template": "https://{bucket}.oss-cn-hangzhou.aliyuncs.com/",
        "not_found": ["NoSuchBucket", "The specified bucket does not exist"],
        "private": ["AccessDenied", "InvalidAccessKeyId"],
        "public": ["ListBucketResult", "<Contents>"],
    },
}

# CNAME suffix → (service_name, provider)
_CLOUD_CNAME_PATTERNS: dict[str, tuple[str, str]] = {
    ".cloudfront.net": ("aws_cloudfront", "aws"),
    ".elasticbeanstalk.com": ("aws_elastic_beanstalk", "aws"),
    ".elb.amazonaws.com": ("aws_elb", "aws"),
    ".s3.amazonaws.com": ("aws_s3", "aws"),
    ".s3-website": ("aws_s3_website", "aws"),
    ".lambda-url.": ("aws_lambda", "aws"),
    ".azurewebsites.net": ("azure_app_service", "azure"),
    ".azurefd.net": ("azure_front_door", "azure"),
    ".azureedge.net": ("azure_cdn", "azure"),
    ".azure-api.net": ("azure_api_management", "azure"),
    ".trafficmanager.net": ("azure_traffic_manager", "azure"),
    ".blob.core.windows.net": ("azure_blob", "azure"),
    ".appspot.com": ("gcp_app_engine", "gcp"),
    ".run.app": ("gcp_cloud_run", "gcp"),
    ".cloudfunctions.net": ("gcp_cloud_functions", "gcp"),
    ".firebaseapp.com": ("firebase", "gcp"),
    ".firebaseio.com": ("firebase", "gcp"),
    ".netlify.app": ("netlify", "netlify"),
    ".netlify.com": ("netlify", "netlify"),
    ".vercel.app": ("vercel", "vercel"),
    ".herokuapp.com": ("heroku", "heroku"),
    ".herokudns.com": ("heroku", "heroku"),
    ".github.io": ("github_pages", "github"),
    ".pages.dev": ("cloudflare_pages", "cloudflare"),
    ".workers.dev": ("cloudflare_workers", "cloudflare"),
    ".shopify.com": ("shopify", "shopify"),
    ".myshopify.com": ("shopify", "shopify"),
    ".squarespace.com": ("squarespace", "squarespace"),
    ".wixsite.com": ("wix", "wix"),
}

# CNAME patterns indicating internet-resolvable database endpoints.
_DB_ENDPOINT_PATTERNS: dict[str, tuple[str, str]] = {
    ".rds.amazonaws.com": ("aws_rds", "aws"),
    ".cache.amazonaws.com": ("aws_elasticache", "aws"),
    ".redshift.amazonaws.com": ("aws_redshift", "aws"),
    ".docdb.amazonaws.com": ("aws_documentdb", "aws"),
    ".database.windows.net": ("azure_sql", "azure"),
    ".database.azure.com": ("azure_database", "azure"),
    ".redis.cache.windows.net": ("azure_redis", "azure"),
    ".documents.azure.com": ("azure_cosmosdb", "azure"),
    ".mongo.cosmos.azure.com": ("azure_cosmosdb_mongo", "azure"),
}

# MX patterns → cloud email provider.
_MX_CLOUD_PATTERNS: dict[str, tuple[str, str]] = {
    ".mail.protection.outlook.com": ("microsoft_365", "microsoft"),
    ".google.com": ("google_workspace", "google"),
    ".googlemail.com": ("google_workspace", "google"),
    ".pphosted.com": ("proofpoint", "proofpoint"),
    ".mimecast.com": ("mimecast", "mimecast"),
}

# TXT record prefixes → cloud verification.
_TXT_CLOUD_PREFIXES: dict[str, tuple[str, str]] = {
    "google-site-verification=": ("google_workspace", "google"),
    "MS=": ("microsoft_365", "microsoft"),
    "amazonses:": ("aws_ses", "aws"),
    "firebase=": ("firebase", "gcp"),
    "atlassian-domain-verification=": ("atlassian", "atlassian"),
    "facebook-domain-verification=": ("facebook", "meta"),
    "docusign=": ("docusign", "docusign"),
    "apple-domain-verification=": ("apple", "apple"),
    "hubspot-developer-verification=": ("hubspot", "hubspot"),
}


def _generate_candidates(domain: str) -> list[str]:
    """Generate candidate bucket names from a domain."""
    domain = domain.lower().strip()
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    bases: list[str] = []
    sanitized_full = domain.replace(".", "-")
    bases.append(sanitized_full)
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        without_tld = parts[0].replace(".", "-")
        if without_tld != sanitized_full:
            bases.append(without_tld)
    else:
        bases.append(domain.replace(".", "-"))

    candidates: list[str] = []
    seen: set[str] = set()
    for base in bases:
        for suffix in _BUCKET_SUFFIXES:
            name = base + suffix
            if name not in seen:
                seen.add(name)
                candidates.append(name)
    return candidates


def _classify_response(body: str, provider_cfg: dict) -> str | None:
    """Classify a response body against provider fingerprints.

    Returns 'public', 'exists_private', or None (not found / unrecognised).
    """
    for marker in provider_cfg["public"]:
        if marker in body:
            return "public"
    for marker in provider_cfg["private"]:
        if marker in body:
            return "exists_private"
    for marker in provider_cfg["not_found"]:
        if marker in body:
            return None
    return None


def detect_cloud_services_from_dns(
    cname_records: list | None = None,
    mx_records: list | None = None,
    txt_records: list | None = None,
) -> list[CloudServiceFinding]:
    """Detect cloud services from DNS records (CNAME, MX, TXT).

    Pure pattern matching — no HTTP requests.
    """
    findings: list[CloudServiceFinding] = []
    seen: set[str] = set()

    for rec in (cname_records or []):
        target = (rec.target if hasattr(rec, "target") else str(rec)).lower()
        for suffix, (service, provider) in _CLOUD_CNAME_PATTERNS.items():
            if suffix in target and service not in seen:
                seen.add(service)
                findings.append(CloudServiceFinding(
                    service=service,
                    provider=provider,
                    record_type="CNAME",
                    record_value=target,
                    severity="info",
                ))

    for rec in (mx_records or []):
        host = (rec.host if hasattr(rec, "host") else str(rec)).lower()
        for suffix, (service, provider) in _MX_CLOUD_PATTERNS.items():
            if host.endswith(suffix) and service not in seen:
                seen.add(service)
                findings.append(CloudServiceFinding(
                    service=service,
                    provider=provider,
                    record_type="MX",
                    record_value=host,
                    severity="info",
                ))

    for rec in (txt_records or []):
        data = (rec.data if hasattr(rec, "data") else str(rec)).strip()
        for prefix, (service, provider) in _TXT_CLOUD_PREFIXES.items():
            if data.lower().startswith(prefix.lower()) and service not in seen:
                seen.add(service)
                findings.append(CloudServiceFinding(
                    service=service,
                    provider=provider,
                    record_type="TXT",
                    record_value=data[:80],
                    severity="info",
                ))

    return findings


def detect_exposed_databases_from_dns(
    cname_records: list | None = None,
) -> list[CloudServiceFinding]:
    """Detect cloud database endpoints resolvable via DNS CNAME records."""
    findings: list[CloudServiceFinding] = []
    seen: set[str] = set()

    for rec in (cname_records or []):
        target = (rec.target if hasattr(rec, "target") else str(rec)).lower()
        for suffix, (service, provider) in _DB_ENDPOINT_PATTERNS.items():
            if suffix in target and target not in seen:
                seen.add(target)
                findings.append(CloudServiceFinding(
                    service=service,
                    provider=provider,
                    record_type="CNAME",
                    record_value=target,
                    is_database=True,
                    severity="high",
                ))

    return findings


async def discover_cloud_assets(
    domain: str,
    *,
    timeout: int = HTTP_TIMEOUT,
    concurrency: int = 10,
) -> CloudAssetResult:
    """Check for publicly accessible cloud storage buckets related to *domain*."""
    candidates = _generate_candidates(domain)
    sem = asyncio.Semaphore(concurrency)
    findings: list[CloudAssetFinding] = []
    buckets_checked = 0
    lock = asyncio.Lock()
    t0 = time.monotonic()

    async def _check(bucket: str, provider_name: str, provider_cfg: dict, client: httpx.AsyncClient) -> None:
        nonlocal buckets_checked
        url = provider_cfg["url_template"].format(bucket=bucket)
        try:
            async with sem:
                resp = await client.get(url)
            body = resp.text
        except Exception:
            async with lock:
                buckets_checked += 1
            return

        status = _classify_response(body, provider_cfg)
        async with lock:
            buckets_checked += 1
            if status is not None:
                evidence: list[str] = []
                for markers_key in ("public", "private"):
                    for marker in provider_cfg[markers_key]:
                        if marker in body:
                            evidence.append(marker)
                if status == "public":
                    # A public listing is directly observable exposure.
                    findings.append(CloudAssetFinding(
                        bucket_name=bucket, provider=provider_name, url=url,
                        status="public",
                        classification="publicly_exposed_bucket",
                        ownership_verified=False,   # name match only; still unproven owner
                        public_exposure_confirmed=True,
                        affects_risk_score=True,
                        evidence=evidence + ["public_listing_observed=true"],
                        severity="high",
                    ))
                else:
                    # AccessDenied / AllAccessDisabled etc. prove neither ownership
                    # nor a security exposure — a guessed name existing somewhere is
                    # an unverified candidate, not a customer bucket.
                    findings.append(CloudAssetFinding(
                        bucket_name=bucket, provider=provider_name, url=url,
                        status="exists_private",
                        classification="unverified_asset_candidate",
                        ownership_verified=False,
                        public_exposure_confirmed=False,
                        affects_risk_score=False,
                        evidence=evidence + [
                            "name_match_only; ownership_verified=false; "
                            "public_exposure_confirmed=false",
                        ],
                        severity="informational",
                    ))

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            verify=False,
        ) as client:
            tasks: list[asyncio.Task] = []
            for candidate in candidates:
                for provider_name, provider_cfg in _PROVIDERS.items():
                    tasks.append(asyncio.ensure_future(
                        _check(candidate, provider_name, provider_cfg, client)
                    ))
            await asyncio.gather(*tasks)
    except Exception as exc:
        logger.warning("Cloud asset discovery failed for %s: %s", domain, exc)
        return CloudAssetResult(
            domain=domain,
            buckets_checked=buckets_checked,
            scan_duration_seconds=round(time.monotonic() - t0, 2),
            error=str(exc),
        )

    elapsed = round(time.monotonic() - t0, 2)
    potential = sum(1 for f in findings if f.classification == "unverified_asset_candidate")
    exposed = sum(1 for f in findings if f.classification == "publicly_exposed_bucket")
    owned = sum(1 for f in findings if f.classification == "confirmed_owned_bucket")
    return CloudAssetResult(
        domain=domain,
        findings=findings,
        buckets_checked=buckets_checked,
        bucket_candidates_checked=buckets_checked,
        potential_bucket_name_matches=potential + exposed,
        confirmed_owned_buckets=owned,
        publicly_exposed_buckets=exposed,
        scan_duration_seconds=elapsed,
    )


def corroborate_cloud_findings(result) -> None:
    """Passively mark name-guessed bucket candidates that the target actually references.

    Sends NO new traffic — cross-references each candidate's bucket name / URL against
    resources the scan already collected (JS intel, external links, supply-chain
    resource URLs, tech evidence, DNS-detected cloud services). A match means the
    bucket is likely a real asset rather than a blind permutation guess; it sets
    ``corroborated=True`` and records the evidence on the finding in place.
    """
    ca = getattr(result, "cloud_assets", None)
    if not ca or not ca.findings:
        return

    # Build a single lowercase haystack from the already-extracted inventories.
    haystack: list[str] = []
    js = getattr(result, "js_intel", None)
    if js:
        haystack += list(js.api_endpoints or [])
        haystack += list(js.internal_hosts or [])
        haystack += list(js.sourcemaps_found or [])
        haystack += list(js.recovered_source_files or [])
    for link in (getattr(result, "external_links", None) or []):
        if getattr(link, "url", ""):
            haystack.append(link.url)
    sc = getattr(result, "supply_chain", None)
    if sc:
        for res in (sc.resources or []):
            if getattr(res, "url", ""):
                haystack.append(res.url)
    for tech in (getattr(result, "technologies", None) or []):
        haystack += list(getattr(tech, "evidence", None) or [])
    # DNS-detected cloud services (CNAME targets) corroborate provider usage.
    for svc in (ca.cloud_services or []):
        if getattr(svc, "record_value", ""):
            haystack.append(svc.record_value)

    hay = "\n".join(h.lower() for h in haystack if h)
    if not hay:
        return

    for f in ca.findings:
        if f.status == "public":
            continue
        name = (f.bucket_name or "").lower()
        # Host portion of the bucket URL, e.g. greyping-com.s3.us-west-004.backblazeb2.com
        url_host = (f.url or "").lower().split("//")[-1].split("/")[0]
        matched: list[str] = []
        if name and len(name) >= 4 and name in hay:
            matched.append(f"bucket name '{f.bucket_name}' referenced in collected resources")
        if url_host and url_host in hay:
            matched.append(f"bucket URL host '{url_host}' referenced in collected resources")
        if matched:
            f.corroborated = True
            f.corroboration = matched


__all__ = [
    "discover_cloud_assets",
    "detect_cloud_services_from_dns",
    "detect_exposed_databases_from_dns",
    "corroborate_cloud_findings",
]
