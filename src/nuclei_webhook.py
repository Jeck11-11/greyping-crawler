"""Background nuclei scan with webhook callback to Xano."""

from __future__ import annotations

import asyncio
import logging

import httpx

from .config import NUCLEI_WEBHOOK_TIMEOUT, XANO_BOARD_WEBHOOK_URL, XANO_WEBHOOK_URL
from .easm_report import build_easm_report
from .fair_signals import compute_fair_signals
from .models import BoardReport, DomainResult, RiskAssessmentGroup
from .nuclei_client import run_nuclei_scan

logger = logging.getLogger(__name__)

_MAX_RETRIES = 3
_BACKOFF_BASE = 2  # seconds


async def _post_webhook(payload: dict, *, url: str = "") -> bool:
    """POST payload to a webhook URL with retry + exponential backoff."""
    url = url or XANO_WEBHOOK_URL
    if not url:
        return False

    for attempt in range(_MAX_RETRIES):
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(NUCLEI_WEBHOOK_TIMEOUT),
            ) as client:
                resp = await client.post(url, json=payload)

                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", _BACKOFF_BASE ** (attempt + 1)))
                    logger.warning(
                        "Webhook rate-limited (429), retrying in %ds", retry_after,
                    )
                    await asyncio.sleep(retry_after)
                    continue

                resp.raise_for_status()
                return True
        except Exception as exc:
            wait = _BACKOFF_BASE ** (attempt + 1)
            logger.warning(
                "Webhook POST failed (attempt %d/%d): %s — retrying in %ds",
                attempt + 1, _MAX_RETRIES, exc, wait,
            )
            await asyncio.sleep(wait)

    logger.error("Webhook POST exhausted %d retries for %s", _MAX_RETRIES, url)
    return False


async def nuclei_background_scan(
    scan_id: str,
    domain_results: list[DomainResult],
) -> None:
    """Run nuclei for each target, re-compute FAIR, POST full result to Xano."""
    for idx, result in enumerate(domain_results):
        try:
            nuclei = await run_nuclei_scan([result.target])

            if result.vulnerabilities:
                result.vulnerabilities.nuclei = nuclei
            result.risk_assessment = RiskAssessmentGroup(
                fair_signals=compute_fair_signals(result, scan_mode="full"),
                easm_report=build_easm_report(result, scan_mode="full"),
            )

            payload = {
                "scan_id": scan_id,
                "target": result.target,
                "nuclei_status": "completed" if not nuclei.error else "error",
                "result": result.model_dump(mode="json"),
            }
            await _post_webhook(payload)
        except Exception as exc:
            logger.exception("Background nuclei scan failed for %s: %s", result.target, exc)

        if idx < len(domain_results) - 1:
            await asyncio.sleep(1)


async def post_board_webhook(
    scan_id: str,
    root_domain: str,
    status: str,
    board_report: BoardReport,
    results: list[DomainResult],
) -> bool:
    """POST completed board report to Xano."""
    payload = {
        "event": "board_report",
        "scan_id": scan_id,
        "root_domain": root_domain,
        "status": status,
        "board_report": board_report.model_dump(mode="json"),
        "results": [r.model_dump(mode="json") for r in results],
    }
    return await _post_webhook(payload, url=XANO_BOARD_WEBHOOK_URL)
