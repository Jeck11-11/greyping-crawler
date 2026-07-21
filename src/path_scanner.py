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
    ("/terms-of-use", "Terms of use page.", "info"),
    ("/terms-and-conditions", "Terms and conditions page.", "info"),
    ("/tos", "Terms of service page.", "info"),
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
    "/terms", "/terms-of-service", "/terms-of-use", "/terms-and-conditions", "/tos",
    "/gdpr", "/ccpa", "/data-request",
    "/.well-known/dnt-policy.txt",
}

# Minimum response body size for a non-info path to count as "really exposed".
# Real .env / backup / config files are never near-empty; a 0-byte or tiny 200
# is a soft-404 / placeholder, not an exposed file.
_MIN_BODY_BYTES = 20

# Improbable paths used to detect catch-all servers (SPAs, wildcard responders)
# that return 200 for everything. If these "exist", status-code probing is
# meaningless and we skip the scan rather than emit false positives.
_SOFT_404_PROBES = (
    "/greyping-soft404-probe-7f3a9b2c1d.html",
    "/this-path-should-not-exist-x9q8w7e6.txt",
)


async def _is_catch_all(client: httpx.AsyncClient, base_url: str) -> bool:
    """Detect a server that returns 200 for paths that should not exist."""
    for probe in _SOFT_404_PROBES:
        try:
            resp = await client.get(
                urljoin(base_url, probe), headers={"User-Agent": UA_HONEST},
            )
        except Exception:
            return False
        if resp.status_code != 200:
            return False
    return True


async def scan_sensitive_paths(
    base_url: str,
    *,
    timeout: int = PATH_SCAN_TIMEOUT,
    concurrency: int = PATH_CONCURRENCY,
) -> list[SensitivePathFinding]:
    """Probe *base_url* for known sensitive paths.

    Only a 200 with real content counts as exposed. 403/redirects are NOT
    treated as existence proof (WAFs/CDNs return 403 for everything), and
    catch-all servers are detected and skipped entirely.
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
                length = int(resp.headers.get("content-length", 0) or 0)
            except Exception:
                return None

            # Only a 200 confirms the path is actually served. A 403 from a
            # WAF/CDN is its default response for countless paths and does NOT
            # mean the file exists.
            if code != 200:
                return None

            # Info/policy pages: existence on 200 is a positive signal.
            if path in _INFO_PATHS:
                return SensitivePathFinding(
                    path=path, url=url, status_code=code,
                    content_length=length, risk=risk, severity=severity,
                )

            # Directory listing detection for directory paths.
            if path.endswith("/"):
                try:
                    get_resp = await client.get(url, headers={"User-Agent": UA_HONEST})
                    body = get_resp.text[:2000]
                    if not any(sig in body for sig in _DIR_LISTING_SIGNATURES):
                        return None
                    risk = "Directory listing enabled — exposes file/folder names."
                    severity = "high"
                    length = len(get_resp.content)
                except Exception:
                    return None
                return SensitivePathFinding(
                    path=path, url=url, status_code=code,
                    content_length=length, risk=risk, severity=severity,
                )

            # Regular file path: confirm it actually returns content. HEAD
            # content-length is unreliable, so GET and measure the real body.
            try:
                get_resp = await client.get(url, headers={"User-Agent": UA_HONEST})
                if get_resp.status_code != 200:
                    return None
                length = len(get_resp.content)
            except Exception:
                return None

            if length < _MIN_BODY_BYTES:
                return None

            # GraphQL introspection probe
            if path == "/graphql":
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
                severity=severity,
            )

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        verify=False,
    ) as client:
        if await _is_catch_all(client, base_url):
            logger.info(
                "Path scan skipped for %s: server returns 200 for nonexistent "
                "paths (catch-all / SPA) — status-code probing unreliable.",
                base_url,
            )
            return []
        tasks = [_check(client, path, risk, sev) for path, risk, sev in _SENSITIVE_PATHS]
        raw = await asyncio.gather(*tasks)
    return [r for r in raw if r is not None]
