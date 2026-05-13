"""Async HTTP client for the ProjectDiscovery httpx probe sidecar."""

from __future__ import annotations

import json
import logging
import time

import httpx

from .config import HTTPX_TIMEOUT, PD_TOOLS_API_URL
from .models import HttpxProbeResult

logger = logging.getLogger(__name__)


def _parse_httpx_jsonl(text: str) -> list[HttpxProbeResult]:
    results: list[HttpxProbeResult] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            results.append(HttpxProbeResult(
                url=obj.get("url", obj.get("input", "")),
                status_code=obj.get("status_code") or obj.get("status-code"),
                title=obj.get("title", ""),
                content_type=obj.get("content_type", obj.get("content-type", "")),
                content_length=int(obj.get("content_length", obj.get("content-length", 0)) or 0),
                technologies=obj.get("tech") or obj.get("technologies") or [],
                webserver=obj.get("webserver", ""),
                response_time=obj.get("response_time", obj.get("response-time", "")),
                host=obj.get("host", ""),
                scheme=obj.get("scheme", ""),
                final_url=obj.get("final_url", obj.get("final-url", "")),
            ))
        except (json.JSONDecodeError, KeyError, ValueError):
            continue
    return results


async def run_httpx_probe(
    targets: list[str],
    *,
    timeout: int = HTTPX_TIMEOUT,
) -> list[HttpxProbeResult]:
    api_url = PD_TOOLS_API_URL
    if not api_url:
        return []

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.post(
                f"{api_url.rstrip('/')}/probe",
                json={
                    "targets": targets,
                    "timeout": timeout,
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.warning("httpx probe failed after %.1fs: %s", elapsed, exc)
        return []

    if "results" in data and isinstance(data["results"], list):
        return [
            HttpxProbeResult(
                url=r.get("url", ""),
                status_code=r.get("status_code"),
                title=r.get("title", ""),
                content_type=r.get("content_type", ""),
                content_length=int(r.get("content_length", 0) or 0),
                technologies=r.get("tech") or r.get("technologies") or [],
                webserver=r.get("webserver", ""),
                response_time=r.get("response_time", ""),
                host=r.get("host", ""),
                scheme=r.get("scheme", ""),
                final_url=r.get("final_url", ""),
            )
            for r in data["results"]
        ]

    return _parse_httpx_jsonl(data.get("stdout", ""))
