"""Async HTTP client for the katana web crawler sidecar."""

from __future__ import annotations

import json
import logging
import time

import httpx

from .config import KATANA_TIMEOUT, PD_TOOLS_API_URL
from .models import KatanaCrawlResult, KatanaEndpoint

logger = logging.getLogger(__name__)


def _parse_katana_jsonl(text: str) -> list[KatanaEndpoint]:
    endpoints: list[KatanaEndpoint] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            req = obj.get("request", {})
            resp = obj.get("response", {})
            url = req.get("endpoint", "") or obj.get("endpoint", "")
            if not url:
                continue
            endpoints.append(KatanaEndpoint(
                url=url,
                method=req.get("method", "GET"),
                source=req.get("source", obj.get("source", "")),
                tag=req.get("tag", obj.get("tag", "")),
                body=resp.get("body", ""),
            ))
        except (json.JSONDecodeError, KeyError):
            continue
    return endpoints


async def run_katana_crawl(
    target: str,
    *,
    max_depth: int = 2,
    timeout: int = KATANA_TIMEOUT,
) -> KatanaCrawlResult:
    api_url = PD_TOOLS_API_URL
    if not api_url:
        return KatanaCrawlResult(target=target, error="PD_TOOLS_API_URL not configured")

    extra_args = f"-depth {max_depth} -js-crawl -known-files all"

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.post(
                f"{api_url.rstrip('/')}/crawl",
                json={
                    "targets": [target],
                    "additional_args": extra_args,
                    "timeout": timeout,
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.warning("Katana crawl failed for %s after %.1fs: %s", target, elapsed, exc)
        return KatanaCrawlResult(target=target, error=str(exc) or type(exc).__name__)

    if "endpoints" in data and isinstance(data["endpoints"], list):
        endpoints = [
            KatanaEndpoint(
                url=e.get("url", ""),
                method=e.get("method", "GET"),
                source=e.get("source", ""),
                tag=e.get("tag", ""),
                body=e.get("body", ""),
            )
            for e in data["endpoints"]
            if e.get("url")
        ]
    else:
        endpoints = _parse_katana_jsonl(data.get("stdout", ""))

    return KatanaCrawlResult(
        target=target,
        endpoints=endpoints,
        error=data.get("error"),
    )
