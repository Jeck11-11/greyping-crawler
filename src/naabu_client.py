"""Async HTTP client for the naabu port scanner sidecar."""

from __future__ import annotations

import json
import logging
import time

import httpx

from .config import NAABU_PORT_RANGE, NAABU_RATE, NAABU_TIMEOUT, PD_TOOLS_API_URL
from .models import NaabuPort, NaabuScanResult

logger = logging.getLogger(__name__)


def _parse_naabu_jsonl(text: str) -> list[NaabuPort]:
    ports: list[NaabuPort] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            ports.append(NaabuPort(
                host=obj.get("host", ""),
                ip=obj.get("ip", ""),
                port=int(obj.get("port", 0)),
                protocol=obj.get("protocol", "tcp"),
            ))
        except (json.JSONDecodeError, KeyError, ValueError):
            continue
    return ports


async def run_naabu_scan(
    host: str,
    *,
    ports: str = NAABU_PORT_RANGE,
    rate: int = NAABU_RATE,
    timeout: int = NAABU_TIMEOUT,
) -> NaabuScanResult:
    api_url = PD_TOOLS_API_URL
    if not api_url:
        return NaabuScanResult(target=host, error="PD_TOOLS_API_URL not configured")

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.post(
                f"{api_url.rstrip('/')}/portscan",
                json={
                    "targets": [host],
                    "ports": ports,
                    "rate": rate,
                    "timeout": timeout,
                },
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.warning("Naabu scan failed for %s after %.1fs: %s", host, elapsed, exc)
        return NaabuScanResult(target=host, error=str(exc) or type(exc).__name__)

    if "ports" in data and isinstance(data["ports"], list):
        found = [
            NaabuPort(
                host=p.get("host", ""),
                ip=p.get("ip", ""),
                port=int(p.get("port", 0)),
                protocol=p.get("protocol", "tcp"),
            )
            for p in data["ports"]
        ]
    else:
        found = _parse_naabu_jsonl(data.get("stdout", ""))

    return NaabuScanResult(
        target=host,
        ports=found,
        error=data.get("error"),
    )
