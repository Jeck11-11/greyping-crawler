"""Attack path analysis — connects individual findings into exploit chains."""

from __future__ import annotations

import logging
from typing import Callable

from .models import (
    AttackPath,
    AttackPathResult,
    AttackStep,
    DomainResult,
)

logger = logging.getLogger(__name__)

_SEV_ORDER = {"critical": 3, "high": 2, "medium": 1, "low": 0}

_ADMIN_PATHS = {
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/administrator", "/administrator/",
    "/admin", "/admin/",
}

_CMS_NAMES = {"WordPress", "Drupal", "Joomla", "Ghost", "Magento"}

_DB_SECRET_TYPES = {"generic_password", "db_url", "mysql_connection", "postgres_connection", "mongodb_connection", "redis_connection"}


def _check_aws_key_to_s3(result: DomainResult) -> AttackPath | None:
    aws_secrets = [s for s in result.secrets if s.secret_type in ("aws_access_key", "aws_secret_key")]
    if not aws_secrets:
        return None
    public_buckets = []
    if result.cloud_assets:
        public_buckets = [f for f in result.cloud_assets.findings if f.status == "public" and "s3" in f.provider]
    if not public_buckets:
        return None

    return AttackPath(
        title="Cloud Data Exfiltration via Exposed AWS Credentials",
        severity="critical",
        impact="data_theft",
        likelihood="confirmed",
        remediation="Immediately rotate the exposed AWS access key and restrict the S3 bucket policy.",
        steps=[
            AttackStep(
                finding_type="SecretFinding",
                description=f"AWS access key exposed on {aws_secrets[0].found_on or 'page source'}",
                fingerprint=aws_secrets[0].fingerprint,
            ),
            AttackStep(
                finding_type="CloudAssetFinding",
                description=f"Public S3 bucket '{public_buckets[0].bucket_name}' accessible without authentication",
                fingerprint=public_buckets[0].fingerprint,
            ),
            AttackStep(
                finding_type="impact",
                description="Attacker uses exposed key to access or exfiltrate data from the public bucket",
            ),
        ],
    )


def _check_env_db_compromise(result: DomainResult) -> AttackPath | None:
    env_paths = [
        p for p in result.sensitive_paths
        if p.status_code == 200 and any(x in p.path.lower() for x in (".env", "config.yml", "config.yaml", "config.json"))
    ]
    if not env_paths:
        return None
    db_secrets = [s for s in result.secrets if s.secret_type in _DB_SECRET_TYPES]
    if not db_secrets:
        return None

    return AttackPath(
        title="Database Compromise via Exposed Configuration File",
        severity="critical",
        impact="data_theft",
        likelihood="confirmed",
        remediation="Remove the configuration file from public access and rotate all database credentials.",
        steps=[
            AttackStep(
                finding_type="SensitivePathFinding",
                description=f"Configuration file '{env_paths[0].path}' accessible (HTTP 200)",
                fingerprint=env_paths[0].fingerprint,
            ),
            AttackStep(
                finding_type="SecretFinding",
                description=f"Database credential ({db_secrets[0].secret_type}) found in page source",
                fingerprint=db_secrets[0].fingerprint,
            ),
            AttackStep(
                finding_type="impact",
                description="Attacker connects to database using leaked credentials for full data access",
            ),
        ],
    )


def _check_admin_rce(result: DomainResult) -> AttackPath | None:
    admin_paths = [p for p in result.sensitive_paths if p.status_code == 200 and p.path in _ADMIN_PATHS]
    if not admin_paths:
        return None
    cms_techs = [t for t in result.technologies if t.name in _CMS_NAMES and t.version]
    if not cms_techs:
        return None
    critical_cves = [c for c in result.cve_findings if c.severity in ("CRITICAL", "HIGH") and c.affected_tech in _CMS_NAMES]
    if not critical_cves:
        return None

    return AttackPath(
        title=f"Remote Code Execution via {cms_techs[0].name} Admin Panel",
        severity="critical",
        impact="code_execution",
        likelihood="likely",
        remediation=f"Restrict access to {admin_paths[0].path}, update {cms_techs[0].name} to the latest version.",
        steps=[
            AttackStep(
                finding_type="SensitivePathFinding",
                description=f"Admin panel '{admin_paths[0].path}' publicly accessible",
                fingerprint=admin_paths[0].fingerprint,
            ),
            AttackStep(
                finding_type="TechFinding",
                description=f"{cms_techs[0].name} {cms_techs[0].version} detected",
            ),
            AttackStep(
                finding_type="CVEFinding",
                description=f"{critical_cves[0].cve_id} ({critical_cves[0].severity}) affects {critical_cves[0].affected_tech}",
                fingerprint=critical_cves[0].fingerprint,
            ),
            AttackStep(
                finding_type="impact",
                description="Attacker exploits known CVE through accessible admin panel to execute arbitrary code",
            ),
        ],
    )


def _check_subdomain_takeover_phishing(result: DomainResult) -> AttackPath | None:
    takeover_findings = []
    if result.vulnerabilities and result.vulnerabilities.subdomain_takeover:
        takeover_findings = [
            f for f in result.vulnerabilities.subdomain_takeover.findings
            if f.status == "vulnerable"
        ]
    if not takeover_findings:
        return None

    insecure_cookies = [c for c in result.cookies if any("Secure" in i for i in c.issues)]

    steps = [
        AttackStep(
            finding_type="SubdomainTakeoverFinding",
            description=f"Subdomain '{takeover_findings[0].subdomain}' vulnerable to takeover via {takeover_findings[0].vulnerable_service}",
            fingerprint=takeover_findings[0].fingerprint,
        ),
        AttackStep(
            finding_type="impact",
            description="Attacker claims the subdomain and hosts a phishing page or intercepts traffic",
        ),
    ]
    if insecure_cookies:
        steps.insert(1, AttackStep(
            finding_type="CookieFinding",
            description=f"Session cookie '{insecure_cookies[0].name}' missing Secure flag — vulnerable to interception on taken-over subdomain",
            fingerprint=insecure_cookies[0].fingerprint,
        ))

    return AttackPath(
        title="Phishing and Session Hijack via Subdomain Takeover",
        severity="critical",
        impact="account_takeover",
        likelihood="confirmed",
        remediation=f"Remove the dangling CNAME record for {takeover_findings[0].subdomain} or reclaim the service.",
        steps=steps,
    )


def _check_github_credential_leak(result: DomainResult) -> AttackPath | None:
    if not (result.vulnerabilities and hasattr(result, "_github_secrets")):
        return None
    return None


def _check_email_spoofing(result: DomainResult) -> AttackPath | None:
    email_sec = result.dns.email_security if result.dns else None
    if not email_sec:
        return None
    dmarc_weak = not email_sec.dmarc.exists or email_sec.dmarc.policy in (None, "none")
    if not dmarc_weak:
        return None
    if not result.emails:
        return None

    return AttackPath(
        title="Email Spoofing and Phishing via Missing DMARC Enforcement",
        severity="high",
        impact="phishing",
        likelihood="confirmed",
        remediation="Configure DMARC with policy=reject and ensure SPF and DKIM are properly set up.",
        steps=[
            AttackStep(
                finding_type="EmailSecurityResult",
                description=f"DMARC {'missing' if not email_sec.dmarc.exists else 'set to p=none (no enforcement)'}",
            ),
            AttackStep(
                finding_type="EmailFinding",
                description=f"{len(result.emails)} email address(es) harvested from the website",
            ),
            AttackStep(
                finding_type="impact",
                description="Attacker sends spoofed emails from the domain to harvested addresses for credential phishing",
            ),
        ],
    )


def _check_internal_network_recon(result: DomainResult) -> AttackPath | None:
    if not result.js_intel or not result.js_intel.internal_hosts:
        return None
    risky_ports = []
    if result.port_scan:
        risky_ports = [p for p in result.port_scan.open_ports if p.is_risky]
    if not risky_ports:
        return None

    return AttackPath(
        title="Internal Network Mapping via JavaScript Intelligence",
        severity="high",
        impact="reconnaissance",
        likelihood="likely",
        remediation="Remove internal hostnames from client-side JavaScript and restrict access to risky services.",
        steps=[
            AttackStep(
                finding_type="JSIntelResult",
                description=f"{len(result.js_intel.internal_hosts)} internal hostname(s) leaked in JavaScript bundles",
            ),
            AttackStep(
                finding_type="OpenPort",
                description=f"Risky port {risky_ports[0].port}/{risky_ports[0].service} open on target",
                fingerprint=risky_ports[0].fingerprint,
            ),
            AttackStep(
                finding_type="impact",
                description="Attacker maps internal network topology and targets exposed services for lateral movement",
            ),
        ],
    )


def _check_sourcemap_reverse_eng(result: DomainResult) -> AttackPath | None:
    if not result.js_intel:
        return None
    if not result.js_intel.sourcemaps_found:
        return None
    if not result.js_intel.api_endpoints:
        return None

    return AttackPath(
        title="Application Reverse Engineering via Exposed Sourcemaps",
        severity="high",
        impact="information_disclosure",
        likelihood="confirmed",
        remediation="Remove sourcemap files from production deployment and restrict API endpoint access.",
        steps=[
            AttackStep(
                finding_type="JSIntelResult",
                description=f"{len(result.js_intel.sourcemaps_found)} sourcemap file(s) publicly accessible",
            ),
            AttackStep(
                finding_type="JSIntelResult",
                description=f"{len(result.js_intel.api_endpoints)} API endpoint(s) discovered in JavaScript",
            ),
            AttackStep(
                finding_type="impact",
                description="Attacker recovers full application source code and maps all API endpoints for targeted exploitation",
            ),
        ],
    )


def _check_session_hijacking(result: DomainResult) -> AttackPath | None:
    ssl_weak = result.ssl.grade in ("D", "E", "F", "") and result.ssl.host
    if not ssl_weak:
        return None
    insecure_session = [c for c in result.cookies if any("Secure" in i for i in c.issues)]
    if not insecure_session:
        return None

    return AttackPath(
        title="Session Hijacking via Weak TLS and Insecure Cookies",
        severity="high",
        impact="account_takeover",
        likelihood="likely",
        remediation="Fix TLS configuration and add the Secure flag to all session cookies.",
        steps=[
            AttackStep(
                finding_type="SSLCertResult",
                description=f"TLS grade '{result.ssl.grade}' — weak encryption allows traffic interception",
            ),
            AttackStep(
                finding_type="CookieFinding",
                description=f"Cookie '{insecure_session[0].name}' transmitted without Secure flag",
                fingerprint=insecure_session[0].fingerprint,
            ),
            AttackStep(
                finding_type="impact",
                description="Attacker intercepts session cookies over weak TLS to impersonate authenticated users",
            ),
        ],
    )


def _check_typosquat_brand_impersonation(result: DomainResult) -> AttackPath | None:
    candidates = []
    if result.typosquatting:
        candidates = result.typosquatting.registered_candidates
    if not candidates:
        return None
    email_sec = result.dns.email_security if result.dns else None
    dmarc_weak = email_sec and (not email_sec.dmarc.exists or email_sec.dmarc.policy in (None, "none"))
    if not dmarc_weak:
        return None

    return AttackPath(
        title="Brand Impersonation via Typosquat Domain and Weak Email Auth",
        severity="medium",
        impact="phishing",
        likelihood="possible",
        remediation="Register defensive typosquat domains and enforce DMARC with policy=reject.",
        steps=[
            AttackStep(
                finding_type="TyposquatCandidate",
                description=f"Lookalike domain '{candidates[0].domain}' is registered and resolving",
                fingerprint=candidates[0].fingerprint,
            ),
            AttackStep(
                finding_type="EmailSecurityResult",
                description="DMARC not enforced — domain can be spoofed in email headers",
            ),
            AttackStep(
                finding_type="impact",
                description="Attacker uses lookalike domain combined with email spoofing for targeted phishing",
            ),
        ],
    )


_CHAIN_RULES: list[Callable[[DomainResult], AttackPath | None]] = [
    _check_aws_key_to_s3,
    _check_env_db_compromise,
    _check_admin_rce,
    _check_subdomain_takeover_phishing,
    _check_github_credential_leak,
    _check_email_spoofing,
    _check_internal_network_recon,
    _check_sourcemap_reverse_eng,
    _check_session_hijacking,
    _check_typosquat_brand_impersonation,
]


def analyze_attack_paths(result: DomainResult) -> AttackPathResult:
    """Analyze a populated DomainResult for exploit chains."""
    paths: list[AttackPath] = []
    for rule in _CHAIN_RULES:
        try:
            path = rule(result)
            if path is not None:
                paths.append(path)
        except Exception as exc:
            logger.debug("Attack path rule %s failed: %s", rule.__name__, exc)

    paths.sort(key=lambda p: _SEV_ORDER.get(p.severity, 0), reverse=True)
    return AttackPathResult(paths=paths, chains_evaluated=len(_CHAIN_RULES))
