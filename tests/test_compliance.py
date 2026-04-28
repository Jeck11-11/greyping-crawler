"""Tests for compliance framework mapping in the EASM report builder."""

from src.easm_report import build_easm_report, _resolve_compliance
from src.models import (
    BreachRecord,
    CookieFinding,
    DomainResult,
    FindingClassification,
    HeaderFinding,
    IoCFinding,
    SecretFinding,
    SecurityHeadersResult,
    SensitivePathFinding,
    SSLCertResult,
    PassiveIntelResult,
    EmailSecurityResult,
    SPFResult,
    DMARCResult,
    DKIMResult,
)


# ---------------------------------------------------------------------------
# _resolve_compliance unit tests
# ---------------------------------------------------------------------------

class TestResolveCompliance:
    def test_exact_match_known_id(self):
        tags = _resolve_compliance("ssl_invalid")
        assert "PCI-DSS 4.1" in tags
        assert "ISO 27001 A.10.1.1" in tags

    def test_prefix_match_secret(self):
        tags = _resolve_compliance("secret_aws_access_key")
        assert "PCI-DSS 3.4" in tags
        assert "GDPR Art.32" in tags
        assert "ISO 27001 A.10.1.1" in tags

    def test_prefix_match_breach(self):
        tags = _resolve_compliance("breach_some_breach")
        assert "PCI-DSS 12.10" in tags
        assert "GDPR Art.33" in tags
        assert "GDPR Art.34" in tags

    def test_prefix_match_cookie(self):
        tags = _resolve_compliance("cookie_my_session")
        assert "PCI-DSS 6.5.10" in tags
        assert "ISO 27001 A.14.1.2" in tags

    def test_prefix_match_path(self):
        tags = _resolve_compliance("path__env")
        assert "PCI-DSS 6.5.8" in tags
        assert "ISO 27001 A.9.4.1" in tags

    def test_prefix_match_ioc_cryptominer(self):
        tags = _resolve_compliance("ioc_cryptominer")
        assert "ISO 27001 A.12.2.1" in tags

    def test_prefix_match_ioc_webshell(self):
        tags = _resolve_compliance("ioc_webshell_path")
        assert "PCI-DSS 11.5" in tags
        assert "ISO 27001 A.12.2.1" in tags

    def test_unknown_id_returns_empty(self):
        tags = _resolve_compliance("totally_unknown_finding_id")
        assert tags == []

    def test_dns_no_ipv6_empty(self):
        tags = _resolve_compliance("dns_no_ipv6")
        assert tags == []


# ---------------------------------------------------------------------------
# Multiple frameworks on a single finding
# ---------------------------------------------------------------------------

class TestMultipleFrameworks:
    def test_exposed_secret_gets_three_frameworks(self):
        """Exposed secrets should be tagged with PCI-DSS, GDPR, and ISO."""
        tags = _resolve_compliance("secret_generic_password")
        frameworks = {t.split(" ")[0] for t in tags}
        assert "PCI-DSS" in frameworks
        assert "GDPR" in frameworks
        assert "ISO" in frameworks

    def test_ssl_invalid_gets_two_frameworks(self):
        tags = _resolve_compliance("ssl_invalid")
        frameworks = {t.split(" ")[0] for t in tags}
        assert "PCI-DSS" in frameworks
        assert "ISO" in frameworks

    def test_breach_gets_two_frameworks(self):
        tags = _resolve_compliance("breach_adobe_2013")
        frameworks = {t.split(" ")[0] for t in tags}
        assert "PCI-DSS" in frameworks
        assert "GDPR" in frameworks


# ---------------------------------------------------------------------------
# Full build_easm_report integration — compliance fields populated
# ---------------------------------------------------------------------------

class TestComplianceInReport:
    def test_findings_get_compliance_tags(self):
        """Findings in the built report have compliance lists populated."""
        result = DomainResult(
            target="https://example.com",
            secrets=[
                SecretFinding(
                    secret_type="aws_access_key",
                    matched_pattern="aws_access_key",
                    value_preview="AKIA...1234",
                    location="script",
                    severity="critical",
                ),
            ],
            ssl_certificate=SSLCertResult(is_valid=False, issues=["expired"]),
        )
        report = build_easm_report(result, scan_mode="full")

        secret_findings = [f for f in report.prioritized_findings if f.id == "secret_aws_access_key"]
        assert len(secret_findings) == 1
        assert "PCI-DSS 3.4" in secret_findings[0].compliance
        assert "GDPR Art.32" in secret_findings[0].compliance

        ssl_findings = [f for f in report.prioritized_findings if f.id == "ssl_invalid"]
        assert len(ssl_findings) == 1
        assert "PCI-DSS 4.1" in ssl_findings[0].compliance

    def test_compliance_summary_populated(self):
        """compliance_summary counts findings per framework correctly."""
        result = DomainResult(
            target="https://example.com",
            secrets=[
                SecretFinding(
                    secret_type="aws_access_key",
                    matched_pattern="aws_access_key",
                    value_preview="AKIA...1234",
                    location="script",
                    severity="critical",
                ),
            ],
            security_headers=SecurityHeadersResult(
                grade="F",
                score=0,
                findings=[
                    HeaderFinding(header="Strict-Transport-Security", status="missing", severity="high"),
                    HeaderFinding(header="Content-Security-Policy", status="missing", severity="high"),
                ],
            ),
        )
        report = build_easm_report(result, scan_mode="full")
        cs = report.compliance_summary

        # At minimum PCI-DSS and ISO should be present
        assert "PCI-DSS" in cs
        assert "ISO" in cs
        # secret contributes PCI-DSS tags + HSTS contributes PCI-DSS tag
        assert cs["PCI-DSS"] >= 3
        assert cs["ISO"] >= 3

    def test_compliance_summary_empty_when_no_findings(self):
        """A clean scan produces an empty compliance_summary."""
        result = DomainResult(
            target="https://example.com",
            ssl_certificate=SSLCertResult(is_valid=True, grade="A"),
        )
        report = build_easm_report(result, scan_mode="full")
        assert report.compliance_summary == {}

    def test_cookie_finding_compliance(self):
        result = DomainResult(
            target="https://example.com",
            cookies=[
                CookieFinding(name="session_id", issues=["Secure flag not set"], severity="high"),
            ],
        )
        report = build_easm_report(result, scan_mode="full")
        cookie_f = [f for f in report.prioritized_findings if f.id == "cookie_session_id"]
        assert len(cookie_f) == 1
        assert "PCI-DSS 6.5.10" in cookie_f[0].compliance

    def test_breach_finding_compliance(self):
        result = DomainResult(
            target="https://example.com",
            breaches=[
                BreachRecord(
                    source="HIBP",
                    breach_name="BigCorp",
                    breach_date="2020-01-01",
                    data_types=["email", "password"],
                ),
            ],
        )
        report = build_easm_report(result, scan_mode="full")
        breach_f = [f for f in report.prioritized_findings if f.id.startswith("breach_")]
        assert len(breach_f) == 1
        assert "PCI-DSS 12.10" in breach_f[0].compliance
        assert "GDPR Art.33" in breach_f[0].compliance
        assert "GDPR Art.34" in breach_f[0].compliance

    def test_email_security_compliance(self):
        result = DomainResult(
            target="https://example.com",
            passive_intel=PassiveIntelResult(
                email_security=EmailSecurityResult(
                    domain="example.com",
                    spf=SPFResult(exists=False),
                    dmarc=DMARCResult(exists=False),
                    dkim=DKIMResult(),
                    grade="F",
                ),
            ),
        )
        report = build_easm_report(result, scan_mode="passive")
        spf_f = [f for f in report.prioritized_findings if f.id == "email_no_spf"]
        assert len(spf_f) == 1
        assert "ISO 27001 A.13.2.1" in spf_f[0].compliance

    def test_ioc_finding_compliance(self):
        result = DomainResult(
            target="https://example.com",
            ioc_findings=[
                IoCFinding(
                    ioc_type="cryptominer",
                    description="CoinHive miner detected",
                    severity="critical",
                ),
            ],
        )
        report = build_easm_report(result, scan_mode="full")
        ioc_f = [f for f in report.prioritized_findings if f.id == "ioc_cryptominer"]
        assert len(ioc_f) == 1
        assert "ISO 27001 A.12.2.1" in ioc_f[0].compliance

    def test_path_finding_compliance(self):
        result = DomainResult(
            target="https://example.com",
            sensitive_paths=[
                SensitivePathFinding(
                    path="/admin",
                    url="https://example.com/admin",
                    status_code=200,
                    severity="high",
                    risk="Admin panel exposed",
                ),
            ],
        )
        report = build_easm_report(result, scan_mode="full")
        path_f = [f for f in report.prioritized_findings if f.id.startswith("path_")]
        assert len(path_f) == 1
        assert "PCI-DSS 6.5.8" in path_f[0].compliance
        assert "ISO 27001 A.9.4.1" in path_f[0].compliance

    def test_compliance_summary_framework_counting(self):
        """Verify that framework_counts increments once per tag, not per finding."""
        result = DomainResult(
            target="https://example.com",
            secrets=[
                SecretFinding(
                    secret_type="aws_access_key",
                    matched_pattern="aws_access_key",
                    value_preview="AKIA...1234",
                    location="script",
                    severity="critical",
                ),
                SecretFinding(
                    secret_type="slack_token",
                    matched_pattern="slack_token",
                    value_preview="xoxb...abcd",
                    location="script",
                    severity="high",
                ),
            ],
        )
        report = build_easm_report(result, scan_mode="full")
        cs = report.compliance_summary
        # Each secret finding adds PCI-DSS 3.4 + PCI-DSS 6.5.x + GDPR Art.32 + ISO A.10.1.1
        # Two secrets -> PCI-DSS count should be 4 (2 findings x 2 PCI tags each)
        assert cs["PCI-DSS"] == 4
        assert cs["GDPR"] == 2
        assert cs["ISO"] == 2
