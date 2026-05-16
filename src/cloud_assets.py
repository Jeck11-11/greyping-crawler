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
                findings.append(CloudAssetFinding(
                    bucket_name=bucket,
                    provider=provider_name,
                    url=url,
                    status=status,
                    evidence=evidence,
                    severity="critical" if status == "public" else "info",
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
    return CloudAssetResult(
        domain=domain,
        findings=findings,
        buckets_checked=buckets_checked,
        scan_duration_seconds=elapsed,
    )


__all__ = [
    "discover_cloud_assets",
    "detect_cloud_services_from_dns",
    "detect_exposed_databases_from_dns",
]
