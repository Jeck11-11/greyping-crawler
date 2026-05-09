"""Tests for attack path analysis engine."""

from __future__ import annotations

from src.attack_paths import analyze_attack_paths
from src.models import (
    AttackPath,
    AttackPathResult,
    AttackStep,
    CloudAssetFinding,
    CloudAssetResult,
    CookieFinding,
    CVEFinding,
    DMARCResult,
    DomainResult,
    DNSGroup,
    EmailFinding,
    EmailSecurityResult,
    JSIntelResult,
    OpenPort,
    PortScanResult,
    SecretFinding,
    SecurityGroup,
    SensitivePathFinding,
    SPFResult,
    SSLCertResult,
    SubdomainTakeoverFinding,
    SubdomainTakeoverResult,
    TechFinding,
    TyposquatCandidate,
    TyposquattingResult,
    VulnerabilitiesGroup,
    ContactsGroup,
)


def _base_result(**kwargs) -> DomainResult:
    return DomainResult(target="https://example.com", **kwargs)


class TestAnalyzeAttackPaths:
    def test_empty_result_no_paths(self):
        result = _base_result()
        ap = analyze_attack_paths(result)
        assert isinstance(ap, AttackPathResult)
        assert ap.paths == []
        assert ap.chains_evaluated == 10

    def test_returns_attack_path_result(self):
        result = _base_result()
        ap = analyze_attack_paths(result)
        assert isinstance(ap, AttackPathResult)


class TestAwsKeyToS3:
    def test_match(self):
        result = _base_result(
            security=SecurityGroup(
                secrets=[SecretFinding(secret_type="aws_access_key", matched_pattern="t", value_preview="AKIA****1234", location="script", found_on="https://example.com/app.js")],
            ),
            cloud_assets=CloudAssetResult(
                domain="example.com",
                findings=[CloudAssetFinding(bucket_name="example-backup", provider="s3_bucket", status="public")],
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "AWS" in p.title), None)
        assert chain is not None
        assert chain.severity == "critical"
        assert chain.impact == "data_theft"
        assert len(chain.steps) == 3

    def test_no_match_without_public_bucket(self):
        result = _base_result(
            security=SecurityGroup(
                secrets=[SecretFinding(secret_type="aws_access_key", matched_pattern="t", value_preview="AKIA****1234", location="script")],
            ),
            cloud_assets=CloudAssetResult(
                domain="example.com",
                findings=[CloudAssetFinding(bucket_name="example-backup", provider="s3_bucket", status="exists_private")],
            ),
        )
        ap = analyze_attack_paths(result)
        assert not any("AWS" in p.title for p in ap.paths)

    def test_no_match_without_aws_key(self):
        result = _base_result(
            cloud_assets=CloudAssetResult(
                domain="example.com",
                findings=[CloudAssetFinding(bucket_name="example-backup", provider="s3_bucket", status="public")],
            ),
        )
        ap = analyze_attack_paths(result)
        assert not any("AWS" in p.title for p in ap.paths)


class TestEnvDbCompromise:
    def test_match(self):
        result = _base_result(
            security=SecurityGroup(
                sensitive_paths=[SensitivePathFinding(path="/.env", status_code=200)],
                secrets=[SecretFinding(secret_type="generic_password", matched_pattern="t", value_preview="pass****word1", location="body")],
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "Database" in p.title), None)
        assert chain is not None
        assert chain.severity == "critical"

    def test_no_match_env_403(self):
        result = _base_result(
            security=SecurityGroup(
                sensitive_paths=[SensitivePathFinding(path="/.env", status_code=403)],
                secrets=[SecretFinding(secret_type="generic_password", matched_pattern="t", value_preview="x", location="body")],
            ),
        )
        ap = analyze_attack_paths(result)
        assert not any("Database" in p.title for p in ap.paths)


class TestAdminRce:
    def test_match(self):
        result = _base_result(
            security=SecurityGroup(
                sensitive_paths=[SensitivePathFinding(path="/wp-admin/", status_code=200)],
            ),
            technologies=[TechFinding(name="WordPress", version="5.2", categories=["cms"], confidence="high")],
            vulnerabilities=VulnerabilitiesGroup(
                cve_findings=[CVEFinding(cve_id="CVE-2024-1234", severity="CRITICAL", affected_tech="WordPress")],
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "Remote Code Execution" in p.title), None)
        assert chain is not None
        assert chain.severity == "critical"
        assert chain.impact == "code_execution"
        assert len(chain.steps) == 4

    def test_no_match_without_cve(self):
        result = _base_result(
            security=SecurityGroup(
                sensitive_paths=[SensitivePathFinding(path="/wp-admin/", status_code=200)],
            ),
            technologies=[TechFinding(name="WordPress", version="5.2", categories=["cms"], confidence="high")],
        )
        ap = analyze_attack_paths(result)
        assert not any("Remote Code" in p.title for p in ap.paths)


class TestSubdomainTakeoverPhishing:
    def test_match(self):
        result = _base_result(
            vulnerabilities=VulnerabilitiesGroup(
                subdomain_takeover=SubdomainTakeoverResult(
                    domain="example.com",
                    findings=[SubdomainTakeoverFinding(
                        subdomain="old.example.com",
                        cname_target="old.github.io",
                        vulnerable_service="GitHub Pages",
                        status="vulnerable",
                        severity="critical",
                    )],
                ),
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "Subdomain Takeover" in p.title), None)
        assert chain is not None
        assert chain.severity == "critical"

    def test_includes_insecure_cookie_step(self):
        result = _base_result(
            security=SecurityGroup(
                cookies=[CookieFinding(name="session", issues=["missing Secure flag"])],
            ),
            vulnerabilities=VulnerabilitiesGroup(
                subdomain_takeover=SubdomainTakeoverResult(
                    domain="example.com",
                    findings=[SubdomainTakeoverFinding(
                        subdomain="old.example.com",
                        cname_target="old.github.io",
                        vulnerable_service="GitHub Pages",
                        status="vulnerable",
                        severity="critical",
                    )],
                ),
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "Subdomain Takeover" in p.title), None)
        assert chain is not None
        assert any("cookie" in s.description.lower() for s in chain.steps)


class TestEmailSpoofing:
    def test_match(self):
        result = _base_result(
            dns=DNSGroup(
                email_security=EmailSecurityResult(
                    domain="example.com",
                    dmarc=DMARCResult(exists=True, policy="none"),
                ),
            ),
            contacts=ContactsGroup(
                emails=[EmailFinding(email="admin@example.com")],
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "Spoofing" in p.title), None)
        assert chain is not None
        assert chain.severity == "high"
        assert chain.impact == "phishing"

    def test_no_match_dmarc_reject(self):
        result = _base_result(
            dns=DNSGroup(
                email_security=EmailSecurityResult(
                    domain="example.com",
                    dmarc=DMARCResult(exists=True, policy="reject"),
                ),
            ),
            contacts=ContactsGroup(
                emails=[EmailFinding(email="admin@example.com")],
            ),
        )
        ap = analyze_attack_paths(result)
        assert not any("Spoofing" in p.title for p in ap.paths)

    def test_no_match_no_emails(self):
        result = _base_result(
            dns=DNSGroup(
                email_security=EmailSecurityResult(
                    domain="example.com",
                    dmarc=DMARCResult(exists=False),
                ),
            ),
        )
        ap = analyze_attack_paths(result)
        assert not any("Spoofing" in p.title for p in ap.paths)


class TestInternalNetworkRecon:
    def test_match(self):
        result = _base_result(
            js_intel=JSIntelResult(
                target="https://example.com",
                scripts_scanned=5,
                api_endpoints=[],
                internal_hosts=["db.internal.example.com"],
            ),
            port_scan=PortScanResult(
                target="example.com",
                open_ports=[OpenPort(port=3306, service="mysql", is_risky=True)],
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "Internal Network" in p.title), None)
        assert chain is not None
        assert chain.severity == "high"

    def test_no_match_without_risky_ports(self):
        result = _base_result(
            js_intel=JSIntelResult(
                target="https://example.com",
                scripts_scanned=5,
                api_endpoints=[],
                internal_hosts=["db.internal.example.com"],
            ),
            port_scan=PortScanResult(
                target="example.com",
                open_ports=[OpenPort(port=443, service="https", is_risky=False)],
            ),
        )
        ap = analyze_attack_paths(result)
        assert not any("Internal Network" in p.title for p in ap.paths)


class TestSourcemapReverseEng:
    def test_match(self):
        result = _base_result(
            js_intel=JSIntelResult(
                target="https://example.com",
                scripts_scanned=5,
                api_endpoints=["/api/v1/users", "/api/v1/auth"],
                internal_hosts=[],
                sourcemaps_found=["https://example.com/app.js.map"],
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "Sourcemap" in p.title), None)
        assert chain is not None
        assert chain.severity == "high"

    def test_no_match_no_sourcemaps(self):
        result = _base_result(
            js_intel=JSIntelResult(
                target="https://example.com",
                scripts_scanned=5,
                api_endpoints=["/api/v1/users"],
                internal_hosts=[],
                sourcemaps_found=[],
            ),
        )
        ap = analyze_attack_paths(result)
        assert not any("Sourcemap" in p.title for p in ap.paths)


class TestSessionHijacking:
    def test_match(self):
        result = _base_result(
            ssl=SSLCertResult(host="example.com", grade="F"),
            security=SecurityGroup(
                cookies=[CookieFinding(name="session_id", issues=["missing Secure flag"])],
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "Session Hijacking" in p.title), None)
        assert chain is not None
        assert chain.severity == "high"

    def test_no_match_good_ssl(self):
        result = _base_result(
            ssl=SSLCertResult(host="example.com", grade="A"),
            security=SecurityGroup(
                cookies=[CookieFinding(name="session_id", issues=["missing Secure flag"])],
            ),
        )
        ap = analyze_attack_paths(result)
        assert not any("Session Hijacking" in p.title for p in ap.paths)


class TestTyposquatBrandImpersonation:
    def test_match(self):
        result = _base_result(
            typosquatting=TyposquattingResult(
                domain="example.com",
                registered_candidates=[TyposquatCandidate(domain="examp1e.com", a_records=["1.2.3.4"])],
            ),
            dns=DNSGroup(
                email_security=EmailSecurityResult(
                    domain="example.com",
                    dmarc=DMARCResult(exists=False),
                ),
            ),
        )
        ap = analyze_attack_paths(result)
        chain = next((p for p in ap.paths if "Brand Impersonation" in p.title), None)
        assert chain is not None
        assert chain.severity == "medium"

    def test_no_match_dmarc_enforced(self):
        result = _base_result(
            typosquatting=TyposquattingResult(
                domain="example.com",
                registered_candidates=[TyposquatCandidate(domain="examp1e.com", a_records=["1.2.3.4"])],
            ),
            dns=DNSGroup(
                email_security=EmailSecurityResult(
                    domain="example.com",
                    dmarc=DMARCResult(exists=True, policy="reject"),
                ),
            ),
        )
        ap = analyze_attack_paths(result)
        assert not any("Brand Impersonation" in p.title for p in ap.paths)


class TestAttackPathFingerprints:
    def test_fingerprint_generated(self):
        path = AttackPath(
            title="Test Path",
            severity="high",
            impact="data_theft",
            steps=[AttackStep(finding_type="SecretFinding", description="test", fingerprint="abc123")],
            likelihood="confirmed",
            remediation="Fix it.",
        )
        assert path.fingerprint
        assert len(path.fingerprint) == 16

    def test_fingerprint_stable(self):
        kwargs = dict(
            title="Test Path",
            severity="high",
            impact="data_theft",
            steps=[AttackStep(finding_type="SecretFinding", description="test", fingerprint="abc123")],
            likelihood="confirmed",
            remediation="Fix it.",
        )
        assert AttackPath(**kwargs).fingerprint == AttackPath(**kwargs).fingerprint

    def test_different_steps_different_fingerprint(self):
        base = dict(title="Test Path", severity="high", impact="data_theft", likelihood="confirmed", remediation="Fix it.")
        p1 = AttackPath(steps=[AttackStep(finding_type="A", description="x", fingerprint="fp1")], **base)
        p2 = AttackPath(steps=[AttackStep(finding_type="B", description="y", fingerprint="fp2")], **base)
        assert p1.fingerprint != p2.fingerprint


class TestSortingAndOrdering:
    def test_critical_before_high(self):
        result = _base_result(
            security=SecurityGroup(
                secrets=[SecretFinding(secret_type="aws_access_key", matched_pattern="t", value_preview="AKIA****1234", location="script")],
                sensitive_paths=[SensitivePathFinding(path="/.env", status_code=200)],
                cookies=[CookieFinding(name="session_id", issues=["missing Secure flag"])],
            ),
            cloud_assets=CloudAssetResult(
                domain="example.com",
                findings=[CloudAssetFinding(bucket_name="example-backup", provider="s3_bucket", status="public")],
            ),
            ssl=SSLCertResult(host="example.com", grade="F"),
        )
        ap = analyze_attack_paths(result)
        if len(ap.paths) >= 2:
            severities = [p.severity for p in ap.paths]
            for i in range(len(severities) - 1):
                sev_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
                assert sev_order.get(severities[i], 0) >= sev_order.get(severities[i + 1], 0)
