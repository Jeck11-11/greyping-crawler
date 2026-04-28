"""Cloud asset discovery — checks for publicly accessible S3, Azure Blob, and GCS buckets."""

from __future__ import annotations

import asyncio
import logging
import time

import httpx

from .config import HTTP_TIMEOUT
from .models import CloudAssetFinding, CloudAssetResult

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
}


def _generate_candidates(domain: str) -> list[str]:
    """Generate candidate bucket names from a domain.

    Uses the full domain and the domain without TLD, applying each suffix.
    Bucket names are lowercased with dots replaced by hyphens.
    """
    domain = domain.lower().strip()
    # Remove protocol if present
    if "://" in domain:
        domain = domain.split("://", 1)[1]
    # Remove path/query
    domain = domain.split("/")[0]
    # Remove port
    domain = domain.split(":")[0]

    bases: list[str] = []
    # Full domain: dots → hyphens for bucket naming
    sanitized_full = domain.replace(".", "-")
    bases.append(sanitized_full)
    # Domain without TLD
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        without_tld = parts[0].replace(".", "-")
        if without_tld != sanitized_full:
            bases.append(without_tld)
    else:
        # No TLD found, just use as-is
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
    # Unrecognised response — treat as not found.
    return None


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
                    severity="critical" if status == "public" else "high",
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


__all__ = ["discover_cloud_assets"]
