"""Search GitHub for leaked secrets referencing a target domain."""

from __future__ import annotations

import asyncio
import logging
import re
import time

import httpx

from .config import GITHUB_API_KEY, GITHUB_SCAN_TIMEOUT
from .models import GitHubSecretFinding, GitHubSecretResult

logger = logging.getLogger(__name__)

_GITHUB_SEARCH_URL = "https://api.github.com/search/code"
_RATE_LIMIT_DELAY = 6.5
_MAX_RESULTS_PER_QUERY = 100

_DORK_TEMPLATES: list[tuple[str, str]] = [
    ("env_file", '"{domain}" filename:.env'),
    ("docker_compose", '"{domain}" filename:docker-compose'),
    ("password", '"{domain}" "password"'),
    ("api_key", '"{domain}" "api_key" OR "api-key" OR "apikey"'),
    ("aws_key", '"{domain}" "AKIA" OR "ASIA"'),
    ("private_key", '"{domain}" "BEGIN RSA PRIVATE KEY" OR "BEGIN EC PRIVATE KEY"'),
    ("db_connection", '"{domain}" "jdbc:" OR "mongodb://" OR "mysql://" OR "redis://"'),
]

_SECRET_VALUE_RE = re.compile(
    r"""(?:password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)"""
    r"""\s*[:=]\s*['"]?([^\s'"]{8,})['"]?""",
    re.IGNORECASE,
)
_AWS_KEY_RE = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")


def _redact_snippet(fragment: str) -> str:
    """Mask secret values in a code snippet."""
    def _mask(m: re.Match) -> str:
        val = m.group(1) if m.lastindex else m.group(0)
        if len(val) <= 8:
            return m.group(0).replace(val, "****")
        return m.group(0).replace(val, val[:4] + "****" + val[-4:])

    result = _SECRET_VALUE_RE.sub(_mask, fragment)
    result = _AWS_KEY_RE.sub(lambda m: m.group(0)[:4] + "****" + m.group(0)[-4:], result)
    return result


async def _search_github(
    client: httpx.AsyncClient,
    query: str,
    api_key: str,
) -> dict:
    """Execute a single GitHub code search query."""
    resp = await client.get(
        _GITHUB_SEARCH_URL,
        params={"q": query, "per_page": _MAX_RESULTS_PER_QUERY},
        headers={
            "Accept": "application/vnd.github.v3.text-match+json",
            "Authorization": f"Bearer {api_key}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    if resp.status_code == 403:
        logger.warning("GitHub rate limit hit")
        return {"total_count": 0, "items": []}
    resp.raise_for_status()
    return resp.json()


async def scan_github_secrets(
    domain: str,
    *,
    timeout: int = GITHUB_SCAN_TIMEOUT,
    api_key: str = "",
) -> GitHubSecretResult:
    """Search GitHub for leaked secrets referencing the given domain."""
    key = api_key or GITHUB_API_KEY
    if not key:
        return GitHubSecretResult(domain=domain, error="GITHUB_API_KEY not configured")

    start = time.monotonic()
    findings: list[GitHubSecretFinding] = []
    seen: set[str] = set()
    queries_run = 0
    total_matches = 0

    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout)) as client:
            for i, (category, template) in enumerate(_DORK_TEMPLATES):
                if i > 0:
                    await asyncio.sleep(_RATE_LIMIT_DELAY)

                query = template.replace("{domain}", domain)
                try:
                    data = await _search_github(client, query, key)
                except Exception as exc:
                    logger.warning("GitHub search failed for %s query %s: %s", domain, category, exc)
                    continue

                queries_run += 1
                total_matches += data.get("total_count", 0)

                for item in data.get("items", []):
                    repo = item.get("repository", {}).get("full_name", "")
                    file_path = item.get("path", "")
                    dedup_key = f"{repo}:{file_path}"

                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    snippet = ""
                    for tm in item.get("text_matches", []):
                        if tm.get("property") == "content":
                            snippet = tm.get("fragment", "")
                            break

                    findings.append(GitHubSecretFinding(
                        query=category,
                        repository=repo,
                        file_path=file_path,
                        file_url=item.get("html_url", ""),
                        code_snippet=_redact_snippet(snippet),
                        last_modified=item.get("repository", {}).get("pushed_at", ""),
                    ))

    except Exception as exc:
        elapsed = round(time.monotonic() - start, 2)
        logger.warning("GitHub secret scan failed for %s: %s", domain, exc)
        return GitHubSecretResult(
            domain=domain,
            findings=findings,
            queries_run=queries_run,
            total_matches=total_matches,
            scan_duration_seconds=elapsed,
            error=str(exc),
        )

    elapsed = round(time.monotonic() - start, 2)
    findings = findings[:50]

    return GitHubSecretResult(
        domain=domain,
        findings=findings,
        queries_run=queries_run,
        total_matches=total_matches,
        scan_duration_seconds=elapsed,
    )
