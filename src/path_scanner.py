"""Probe a target for commonly exposed sensitive paths."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urljoin

import httpx

from .config import PATH_CONCURRENCY, PATH_SCAN_TIMEOUT, UA_HONEST
from .models import SensitivePathFinding

logger = logging.getLogger(__name__)

# (path, risk description, severity)
_SENSITIVE_PATHS: list[tuple[str, str, str]] = [
    ("/.env", "Environment file may contain secrets, DB credentials, and API keys.", "critical"),
    ("/.git/config", "Exposed Git config can reveal repo URL, branches, and credentials.", "critical"),
    ("/.git/HEAD", "Exposed Git HEAD confirms the .git directory is publicly accessible.", "critical"),
    ("/wp-config.php.bak", "WordPress config backup may contain DB passwords.", "critical"),
    ("/wp-config.php~", "WordPress config editor backup may contain DB passwords.", "critical"),
    ("/.htaccess", "Apache config may reveal rewrite rules, auth, or internal paths.", "high"),
    ("/.htpasswd", "Apache password file may contain hashed credentials.", "critical"),
    ("/debug.log", "Debug log may contain stack traces, secrets, and internal paths.", "high"),
    ("/error.log", "Error log may contain stack traces and internal details.", "medium"),
    ("/server-status", "Apache server-status page leaks active connections and URLs.", "high"),
    ("/server-info", "Apache server-info page leaks full server configuration.", "high"),
    ("/phpinfo.php", "phpinfo() leaks PHP version, extensions, and environment variables.", "high"),
    ("/info.php", "PHP info page leaks server configuration.", "high"),
    ("/.DS_Store", "macOS directory index may reveal hidden files and directory structure.", "medium"),
    ("/robots.txt", "robots.txt may reveal hidden or sensitive paths.", "info"),
    ("/sitemap.xml", "Sitemap reveals the full URL structure of the site.", "info"),
    ("/.well-known/security.txt", "security.txt is recommended; absence isn't a vulnerability.", "info"),
    ("/wp-login.php", "WordPress login page is exposed (consider restricting access).", "low"),
    ("/wp-admin/", "WordPress admin area is publicly reachable.", "low"),
    ("/administrator/", "Joomla admin area is publicly reachable.", "low"),
    ("/admin/", "Admin panel path is publicly reachable.", "low"),
    ("/backup/", "Backup directory may contain database dumps or file archives.", "high"),
    ("/backup.zip", "Backup archive may contain full source code and credentials.", "critical"),
    ("/backup.sql", "SQL dump may contain full database contents.", "critical"),
    ("/database.sql", "SQL dump may contain full database contents.", "critical"),
    ("/dump.sql", "SQL dump may contain full database contents.", "critical"),
    ("/config.yml", "Config file may contain secrets and internal settings.", "high"),
    ("/config.yaml", "Config file may contain secrets and internal settings.", "high"),
    ("/config.json", "Config file may contain secrets and internal settings.", "high"),
    ("/.dockerenv", "Docker environment marker reveals containerised deployment.", "low"),
    ("/Dockerfile", "Dockerfile may reveal build secrets and internal architecture.", "medium"),
    ("/docker-compose.yml", "Compose file may reveal service topology and credentials.", "high"),
    ("/package.json", "Node package.json reveals dependencies and scripts.", "low"),
    ("/composer.json", "PHP composer.json reveals dependencies.", "low"),
    ("/Gemfile", "Ruby Gemfile reveals dependencies.", "low"),
]

# Paths at info severity are always reported when found; others only on
# interesting status codes.
_INFO_PATHS = {"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}

# Status codes that indicate the path exists and is accessible.
# 301/302 are excluded — redirects (common on Wix, CDNs, etc.) do NOT
# mean the sensitive file is exposed.
_INTERESTING_CODES = {200, 403}


async def scan_sensitive_paths(
    base_url: str,
    *,
    timeout: int = PATH_SCAN_TIMEOUT,
    concurrency: int = PATH_CONCURRENCY,
) -> list[SensitivePathFinding]:
    """Probe *base_url* for known sensitive paths.

    Returns findings for paths that appear to exist (2xx/3xx/403).
    """
    sem = asyncio.Semaphore(concurrency)
    results: list[SensitivePathFinding | None] = []

    async def _check(path: str, risk: str, severity: str) -> SensitivePathFinding | None:
        url = urljoin(base_url, path)
        async with sem:
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(timeout),
                    follow_redirects=False,
                    verify=False,
                ) as client:
                    resp = await client.head(url, headers={
                        "User-Agent": UA_HONEST,
                    })
                    code = resp.status_code
                    length = int(resp.headers.get("content-length", 0))
            except Exception:
                return None

            if code not in _INTERESTING_CODES:
                return None

            # 403 on info paths is not interesting
            if path in _INFO_PATHS and code == 403:
                return None

            # For info paths, only report 200
            if path in _INFO_PATHS and code != 200:
                return None

            # Skip if it's a generic 200 with a tiny body (custom 404 pages)
            if code == 200 and length > 0 and length < 20 and path not in _INFO_PATHS:
                return None

            return SensitivePathFinding(
                path=path,
                url=url,
                status_code=code,
                content_length=length,
                risk=risk,
                severity=severity if code != 403 else "medium",
            )

    tasks = [_check(path, risk, sev) for path, risk, sev in _SENSITIVE_PATHS]
    raw = await asyncio.gather(*tasks)
    return [r for r in raw if r is not None]
