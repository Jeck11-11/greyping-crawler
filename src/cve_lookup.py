"""CVE correlation from detected technology versions via osv.dev API."""

from __future__ import annotations

import asyncio
import logging
from typing import Sequence

import httpx

from .config import CVE_LOOKUP_TIMEOUT
from .models import CVEFinding, TechFinding

logger = logging.getLogger(__name__)

_OSV_API = "https://api.osv.dev/v1/query"

_TECH_TO_OSV: dict[str, tuple[str, str]] = {
    "jQuery": ("jquery", "npm"),
    "Angular": ("@angular/core", "npm"),
    "Next.js": ("next", "npm"),
    "Vue.js": ("vue", "npm"),
    "React": ("react", "npm"),
    "Lodash": ("lodash", "npm"),
    "Bootstrap": ("bootstrap", "npm"),
    "Express": ("express", "npm"),
    "Drupal": ("drupal/core", "Packagist"),
    "Laravel": ("laravel/framework", "Packagist"),
    "Symfony": ("symfony/symfony", "Packagist"),
    "Django": ("Django", "PyPI"),
    "Flask": ("Flask", "PyPI"),
    "Rails": ("rails", "RubyGems"),
    "WordPress": ("wordpress", ""),
    "Nginx": ("nginx", ""),
    "Apache": ("apache", ""),
    "PHP": ("php", ""),
}

_SEVERITY_MAP = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}


def _extract_severity(vuln: dict) -> tuple[str, float | None]:
    for sev in vuln.get("severity") or []:
        score_str = sev.get("score", "")
        sev_type = sev.get("type", "")
        if sev_type == "CVSS_V3" and score_str:
            try:
                score = float(score_str.split("/")[0]) if "/" in score_str else float(score_str)
            except (ValueError, IndexError):
                score = None
            if score is not None:
                if score >= 9.0:
                    return "CRITICAL", score
                if score >= 7.0:
                    return "HIGH", score
                if score >= 4.0:
                    return "MEDIUM", score
                return "LOW", score
    eco_severity = (vuln.get("database_specific") or {}).get("severity", "")
    if eco_severity.upper() in _SEVERITY_MAP:
        return eco_severity.upper(), None
    return "", None


async def _query_osv(
    client: httpx.AsyncClient,
    package_name: str,
    ecosystem: str,
    version: str,
    tech_name: str,
) -> list[CVEFinding]:
    body: dict = {"version": version, "package": {"name": package_name}}
    if ecosystem:
        body["package"]["ecosystem"] = ecosystem

    try:
        resp = await client.post(_OSV_API, json=body)
        if resp.status_code != 200:
            return []
        data = resp.json()
    except Exception as exc:
        logger.debug("OSV query failed for %s %s: %s", tech_name, version, exc)
        return []

    findings: list[CVEFinding] = []
    for vuln in data.get("vulns") or []:
        aliases = vuln.get("aliases") or []
        cve_ids = [a for a in aliases if a.startswith("CVE-")]
        vuln_id = cve_ids[0] if cve_ids else vuln.get("id", "")
        if not vuln_id:
            continue

        severity, cvss = _extract_severity(vuln)
        summary = vuln.get("summary") or vuln.get("details", "")
        if len(summary) > 300:
            summary = summary[:297] + "..."

        refs = vuln.get("references") or []
        ref_url = ""
        for r in refs:
            if r.get("type") in ("WEB", "ADVISORY"):
                ref_url = r.get("url", "")
                break
        if not ref_url and refs:
            ref_url = refs[0].get("url", "")

        findings.append(CVEFinding(
            cve_id=vuln_id,
            description=summary,
            severity=severity,
            cvss_score=cvss,
            affected_tech=tech_name,
            affected_version=version,
            reference_url=ref_url,
        ))

    return findings


async def lookup_cves(
    technologies: Sequence[TechFinding],
    *,
    timeout: int = CVE_LOOKUP_TIMEOUT,
) -> list[CVEFinding]:
    candidates = [
        t for t in technologies
        if t.version and t.name in _TECH_TO_OSV
    ]
    if not candidates:
        return []

    all_findings: list[CVEFinding] = []
    async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
        tasks = []
        for tech in candidates:
            pkg_name, ecosystem = _TECH_TO_OSV[tech.name]
            tasks.append(_query_osv(client, pkg_name, ecosystem, tech.version, tech.name))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_findings.extend(r)

    seen: set[str] = set()
    deduped: list[CVEFinding] = []
    for f in all_findings:
        if f.cve_id not in seen:
            seen.add(f.cve_id)
            deduped.append(f)

    deduped.sort(key=lambda f: _SEVERITY_MAP.get(f.severity, 0), reverse=True)
    return deduped[:50]
