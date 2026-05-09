"""Probe a target for commonly exposed sensitive paths."""

from __future__ import annotations

import asyncio
import logging
from urllib.parse import urljoin

import httpx

from .config import PATH_CONCURRENCY, PATH_SCAN_TIMEOUT, UA_HONEST
from .models import SensitivePathFinding

logger = logging.getLogger(__name__)

_DIR_LISTING_SIGNATURES = (
    "<title>Index of", "Directory listing for", "<title>Directory Listing",
    "Parent Directory</a>", "[To Parent Directory]",
)

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
    ("/.git/index", "Exposed Git index can be used to reconstruct the full source tree.", "critical"),
    ("/.aws/credentials", "AWS credentials file may contain access keys.", "critical"),
    ("/graphql", "GraphQL endpoint may allow introspection queries.", "medium"),
    ("/node_modules/.package-lock.json", "Exposed node_modules confirms dependency leak.", "medium"),
    # Directory listing probes
    ("/uploads/", "Upload directory listing may expose user-uploaded content.", "high"),
    ("/images/", "Image directory listing exposes file structure.", "medium"),
    ("/assets/", "Asset directory listing exposes file structure.", "medium"),
    ("/files/", "File directory listing may expose sensitive documents.", "high"),
    ("/media/", "Media directory listing may expose uploaded content.", "medium"),
    # Privacy / compliance pages
    ("/privacy", "Privacy policy page.", "info"),
    ("/privacy-policy", "Privacy policy page.", "info"),
    ("/cookie-policy", "Cookie consent policy page.", "info"),
    ("/terms", "Terms of service page.", "info"),
    ("/terms-of-service", "Terms of service page.", "info"),
    ("/gdpr", "GDPR compliance page.", "info"),
    ("/ccpa", "CCPA compliance page.", "info"),
    ("/data-request", "Data subject request form (GDPR/CCPA).", "info"),
    ("/.well-known/dnt-policy.txt", "Do Not Track policy.", "info"),
]

# Paths at info severity are always reported when found; others only on
# interesting status codes.
_INFO_PATHS = {
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/privacy", "/privacy-policy", "/cookie-policy",
    "/terms", "/terms-of-service",
    "/gdpr", "/ccpa", "/data-request",
    "/.well-known/dnt-policy.txt",
}

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

    async def _check(
        client: httpx.AsyncClient, path: str, risk: str, severity: str,
    ) -> SensitivePathFinding | None:
        url = urljoin(base_url, path)
        async with sem:
            try:
                resp = await client.head(url, headers={"User-Agent": UA_HONEST})
                code = resp.status_code
                # Fallback to GET if server rejects HEAD
                if code == 405:
                    resp = await client.get(url, headers={"User-Agent": UA_HONEST})
                    code = resp.status_code
                length = int(resp.headers.get("content-length", 0))
            except Exception:
                return None

            if code not in _INTERESTING_CODES:
                return None

            if path in _INFO_PATHS and code == 403:
                return None

            if path in _INFO_PATHS and code != 200:
                return None

            if code == 200 and length > 0 and length < 20 and path not in _INFO_PATHS:
                return None

            # Directory listing detection for directory paths
            if code == 200 and path.endswith("/") and path not in _INFO_PATHS:
                try:
                    get_resp = await client.get(url, headers={"User-Agent": UA_HONEST})
                    body = get_resp.text[:2000]
                    if not any(sig in body for sig in _DIR_LISTING_SIGNATURES):
                        return None
                    risk = "Directory listing enabled — exposes file/folder names."
                    severity = "high"
                except Exception:
                    return None

            # GraphQL introspection probe
            if path == "/graphql" and code == 200:
                try:
                    gql_resp = await client.post(
                        url,
                        headers={"User-Agent": UA_HONEST, "Content-Type": "application/json"},
                        json={"query": "{__schema{types{name}}}"},
                    )
                    if gql_resp.status_code == 200 and "__schema" in gql_resp.text:
                        risk = "GraphQL introspection enabled — full API schema is queryable."
                        severity = "high"
                except Exception:
                    pass

            return SensitivePathFinding(
                path=path,
                url=url,
                status_code=code,
                content_length=length,
                risk=risk,
                severity=severity if code != 403 else "medium",
            )

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        verify=False,
    ) as client:
        tasks = [_check(client, path, risk, sev) for path, risk, sev in _SENSITIVE_PATHS]
        raw = await asyncio.gather(*tasks)
    return [r for r in raw if r is not None]
