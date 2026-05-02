"""Async HTTP client for the Nuclei API sidecar."""

from __future__ import annotations

import json
import logging
import os
import time

import httpx

from .config import NUCLEI_API_URL, NUCLEI_TIMEOUT
from .models import NucleiFinding, NucleiResult

logger = logging.getLogger(__name__)


def _parse_jsonl_findings(text: str) -> list[NucleiFinding]:
    findings: list[NucleiFinding] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
            info = obj.get("info") or {}
            findings.append(NucleiFinding(
                template_id=obj.get("template-id", obj.get("templateID", "")),
                name=info.get("name", ""),
                severity=info.get("severity", ""),
                type=obj.get("type", ""),
                matched_at=obj.get("matched-at", obj.get("matched", "")),
                description=info.get("description", ""),
                reference=info.get("reference") or [],
                extracted_results=obj.get("extracted-results") or [],
                tags=info.get("tags") or [],
            ))
        except (json.JSONDecodeError, KeyError):
            continue
    return findings


def _read_output_file(path: str) -> list[NucleiFinding]:
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path) as f:
            return _parse_jsonl_findings(f.read())
    except OSError:
        return []


async def run_nuclei_scan(
    targets: list[str],
    *,
    severity: str = "info,low,medium,high,critical",
    tags: str = "",
    timeout: int = NUCLEI_TIMEOUT,
) -> NucleiResult:
    nuclei_url = NUCLEI_API_URL
    if not nuclei_url:
        return NucleiResult(
            target=targets[0] if targets else "",
            error="NUCLEI_API_URL not configured",
        )

    extra_args_parts = [f"-severity {severity}"]
    if tags:
        extra_args_parts.append(f"-tags {tags}")
    extra_args = " ".join(extra_args_parts)

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            resp = await client.post(
                f"{nuclei_url.rstrip('/')}/scan",
                json={"targets": targets, "additional_args": extra_args},
            )
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.warning("Nuclei scan failed: %s", exc)
        return NucleiResult(
            target=targets[0] if targets else "",
            scan_duration_seconds=round(elapsed, 2),
            error=str(exc),
        )

    elapsed = time.monotonic() - start

    # Handle structured response (new format) or raw JSONL (legacy)
    if "findings" in data and isinstance(data["findings"], list):
        findings = [
            NucleiFinding(
                template_id=f.get("template_id", ""),
                name=f.get("name", ""),
                severity=f.get("severity", ""),
                type=f.get("type", ""),
                matched_at=f.get("matched_at", ""),
                description=f.get("description", ""),
                reference=f.get("reference") or [],
                extracted_results=f.get("extracted_results") or [],
                tags=f.get("tags") or [],
            )
            for f in data["findings"]
        ]
        templates_run = (data.get("stats") or {}).get("templates", 0)
    else:
        findings = _parse_jsonl_findings(data.get("stdout") or "")
        if not findings:
            findings = _read_output_file(data.get("output_file", ""))
        templates_run = 0

    return NucleiResult(
        target=targets[0] if targets else "",
        findings=findings,
        templates_run=templates_run,
        scan_duration_seconds=round(elapsed, 2),
    )
