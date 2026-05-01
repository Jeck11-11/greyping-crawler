"""Tests for the EASM report builder."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.app import app
from src.easm_report import build_easm_report, _detect_primary_platform
from src.models import (
    CookieFinding,
    CTResult,
    DKIMResult,
    DMARCResult,
    DNSGroup,
    DNSResult,
    DomainResult,
    EmailSecurityResult,
    FindingClassification,
    FindingOwner,
    HeaderFinding,
    JSIntelResult,
    MXRecord,
    PassiveIntelSlim,
    RDAPResult,
    SecurityGroup,
    SPFResult,
    SSLCertResult,
    SecretFinding,
    SecurityHeadersResult,
    SensitivePathFinding,
    TechFinding,
    WaybackResult,
)


client = TestClient(app)


# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------

class TestPlatformDetection:
    def test_detects_wix_from_tech_fingerprint(self):
        result = DomainResult(
            target="https://example.com",
            technologies=[TechFinding(name="Wix", categories=["cms"], confidence="high")],
        )
        name, profile = _detect_primary_platform(result)
        assert name == "Wix"
        assert "XSRF-TOKEN" in profile.known_cookies

    def test_detects_shopify_from_tech(self):
        result = DomainResult(
            target="https://example.com",
            technologies=[TechFinding(name="Shopify", categories=["ecommerce"], confidence="medium")],
        )
        name, _ = _detect_primary_platform(result)
        assert name == "Shopify"

    def test_ignores_low_confidence_tech(self):
        result = DomainResult(
            target="https://example.com",
            technologies=[TechFinding(name="Wix", categories=["cms"], confidence="low")],
        )
        name, _ = _detect_primary_platform(result)
        assert name == ""

    def test_no_platform_detected(self):
        result = DomainResult(target="https://example.com")
        name, profile = _detect_primary_platform(result)
        assert name == ""
        assert not profile.owns_infrastructure


# ---------------------------------------------------------------------------
# Header classification
# ---------------------------------------------------------------------------

class TestHeaderClassification:
    def test_missing_header_on_wix_is_platform_behavior(self):
        result = DomainResult(
            target="https://example.com",
            technologies=[TechFinding(name="Wix", categories=["cms"], confidence="high")],
            security=SecurityGroup(
                headers=SecurityHeadersResult(
                    grade="D", score=30,
                    findings=[
                        HeaderFinding(header="Content-Security-Policy", status="missing", severity="high"),
                    ],
                ),
            ),
        )
        report = build_easm_report(result, scan_mode="full")
        csp_findings = [f for f in report.prioritized_findings if f.id == "missing_content_security_policy"]
        assert len(csp_findings) == 1
        assert csp_findings[0].classification == FindingClassification.platform_behavior
        assert csp_findings[0].owner == FindingOwner.platform

    def test_missing_header_on_custom_site_is_confirmed(self):
        result = DomainResult(
            target="https://example.com",
            security=SecurityGroup(headers=SecurityHeadersResult(
                grade="D", score=30,
                findings=[
                    HeaderFinding(header="Strict-Transport-Security", status="missing", severity="high"),
                ],
            )),
        )
        report = build_easm_report(result, scan_mode="full")
        hsts = [f for f in report.prioritized_findings if f.id == "missing_strict_transport_security"]
        assert len(hsts) == 1
        assert hsts[0].classification == FindingClassification.confirmed_issue
        assert hsts[0].owner == FindingOwner.customer


# ---------------------------------------------------------------------------
# Cookie classification
# ---------------------------------------------------------------------------

class TestCookieClassification:
    def test_xsrf_token_always_platform_behavior(self):
        result = DomainResult(
            target="https://example.com",
            security=SecurityGroup(cookies=[
                CookieFinding(name="XSRF-TOKEN", issues=["HttpOnly flag not set"], severity="medium"),
            ]),
        )
        report = build_easm_report(result, scan_mode="full")
        cookie_f = [f for f in report.prioritized_findings if f.id == "cookie_XSRF-TOKEN"]
        assert len(cookie_f) == 1
        assert cookie_f[0].classification == FindingClassification.platform_behavior

    def test_custom_cookie_is_confirmed_issue(self):
        result = DomainResult(
            target="https://example.com",
            security=SecurityGroup(cookies=[
                CookieFinding(name="my_session", issues=["Secure flag not set"], severity="high"),
            ]),
        )
        report = build_easm_report(result, scan_mode="full")
        cookie_f = [f for f in report.prioritized_findings if f.id == "cookie_my_session"]
        assert len(cookie_f) == 1
        assert cookie_f[0].classification == FindingClassification.confirmed_issue

    def test_cookie_classification_counts(self):
        result = DomainResult(
            target="https://example.com",
            technologies=[TechFinding(name="Wix", categories=["cms"], confidence="high")],
            security=SecurityGroup(cookies=[
                CookieFinding(name="XSRF-TOKEN", issues=["HttpOnly flag not set"], severity="medium"),
                CookieFinding(name="hs", issues=["Secure flag not set"], severity="medium"),
                CookieFinding(name="my_custom", issues=["Secure flag not set"], severity="high"),
                CookieFinding(name="clean_cookie"),
            ]),
        )
        report = build_easm_report(result, scan_mode="full")
        cookie_findings = [f for f in report.prioritized_findings if f.category == "cookies"]
        platform_findings = [f for f in cookie_findings if f.classification == FindingClassification.platform_behavior]
        customer_findings = [f for f in cookie_findings if f.classification == FindingClassification.confirmed_issue]
        assert len(cookie_findings) == 3
        assert len(platform_findings) == 2
        assert len(customer_findings) == 1


# ---------------------------------------------------------------------------
# Email security classification
# ---------------------------------------------------------------------------

class TestEmailSecurityClassification:
    def test_missing_spf_and_dmarc(self):
        result = DomainResult(
            target="https://example.com",
            dns=DNSGroup(email_security=EmailSecurityResult(
                domain="example.com",
                spf=SPFResult(exists=False),
                dmarc=DMARCResult(exists=False),
                dkim=DKIMResult(),
                grade="F",
            )),
        )
        report = build_easm_report(result, scan_mode="passive")
        ids = {f.id for f in report.prioritized_findings}
        assert "email_no_spf" in ids
        assert "email_no_dmarc" in ids
        assert "email_no_dkim" in ids

    def test_dmarc_none_is_informational(self):
        result = DomainResult(
            target="https://example.com",
            dns=DNSGroup(email_security=EmailSecurityResult(
                domain="example.com",
                spf=SPFResult(exists=True, all_qualifier="-all"),
                dmarc=DMARCResult(exists=True, policy="none", raw="v=DMARC1; p=none"),
                dkim=DKIMResult(selectors_found=["google"]),
                grade="C",
            )),
        )
        report = build_easm_report(result, scan_mode="passive")
        dmarc_f = [f for f in report.prioritized_findings if f.id == "email_dmarc_none"]
        assert len(dmarc_f) == 1
        assert dmarc_f[0].classification == FindingClassification.informational


# ---------------------------------------------------------------------------
# Prioritization sort order
# ---------------------------------------------------------------------------

class TestSortOrder:
    def test_critical_customer_before_medium_platform(self):
        result = DomainResult(
            target="https://example.com",
            technologies=[TechFinding(name="Wix", categories=["cms"], confidence="high")],
            security=SecurityGroup(
                secrets=[
                    SecretFinding(
                        secret_type="aws_access_key", matched_pattern="aws_access_key",
                        value_preview="AKIA...1234", location="script", severity="critical",
                    ),
                ],
                headers=SecurityHeadersResult(
                    grade="D", score=30,
                    findings=[
                        HeaderFinding(header="Content-Security-Policy", status="missing", severity="high"),
                    ],
                ),
            ),
        )
        report = build_easm_report(result, scan_mode="full")
        assert len(report.prioritized_findings) >= 2
        assert report.prioritized_findings[0].category == "secrets"
        assert report.prioritized_findings[0].severity == "critical"


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

class TestExecutiveSummary:
    def test_clean_scan_low_risk(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=True, grade="A"),
        )
        report = build_easm_report(result, scan_mode="full")
        assert report.executive_summary.risk_posture == "Low"
        assert "No evidence of leaked secrets" in report.executive_summary.narrative

    def test_secrets_found_raises_risk(self):
        result = DomainResult(
            target="https://example.com",
            security=SecurityGroup(secrets=[
                SecretFinding(
                    secret_type="aws_access_key", matched_pattern="aws_access_key",
                    value_preview="AKIA...1234", location="script", severity="critical",
                ),
            ]),
        )
        report = build_easm_report(result, scan_mode="full")
        assert report.executive_summary.risk_posture in ("High", "Critical")
        assert "credential" in report.executive_summary.narrative.lower()

    def test_platform_context_in_narrative(self):
        result = DomainResult(
            target="https://example.com",
            technologies=[TechFinding(name="Wix", categories=["cms"], confidence="high")],
        )
        report = build_easm_report(result, scan_mode="full")
        assert "Wix" in report.executive_summary.narrative

    def test_passive_scan_coverage(self):
        result = DomainResult(target="https://example.com")
        report = build_easm_report(result, scan_mode="passive")
        assert report.executive_summary.scan_coverage == "passive"
        assert "passive" in report.executive_summary.narrative


# ---------------------------------------------------------------------------
# Sensitive paths — info paths suppressed
# ---------------------------------------------------------------------------

class TestPathClassification:
    def test_info_paths_suppressed(self):
        result = DomainResult(
            target="https://example.com",
            security=SecurityGroup(sensitive_paths=[
                SensitivePathFinding(path="/robots.txt", url="https://example.com/robots.txt",
                                     status_code=200, severity="info"),
            ]),
        )
        report = build_easm_report(result, scan_mode="full")
        path_findings = [f for f in report.prioritized_findings if f.category == "sensitive_paths"]
        assert len(path_findings) == 0

    def test_critical_path_200_is_confirmed(self):
        result = DomainResult(
            target="https://example.com",
            security=SecurityGroup(sensitive_paths=[
                SensitivePathFinding(path="/.env", url="https://example.com/.env",
                                     status_code=200, severity="critical", risk="Environment file with credentials"),
            ]),
        )
        report = build_easm_report(result, scan_mode="full")
        env_f = [f for f in report.prioritized_findings if "env" in f.id]
        assert len(env_f) == 1
        assert env_f[0].classification == FindingClassification.confirmed_issue
        assert env_f[0].severity == "critical"


# ---------------------------------------------------------------------------
# Report counts
# ---------------------------------------------------------------------------

class TestReportCounts:
    def test_counts_match_findings(self):
        result = DomainResult(
            target="https://example.com",
            dns=DNSGroup(email_security=EmailSecurityResult(
                domain="example.com",
                spf=SPFResult(exists=False),
                dmarc=DMARCResult(exists=False),
                dkim=DKIMResult(),
                grade="F",
            )),
        )
        report = build_easm_report(result, scan_mode="passive")
        assert report.total_findings == len(report.prioritized_findings)
        assert report.confirmed_issues == sum(
            1 for f in report.prioritized_findings
            if f.classification == FindingClassification.confirmed_issue
        )
        assert report.informational_count == sum(
            1 for f in report.prioritized_findings
            if f.classification == FindingClassification.informational
        )


# ---------------------------------------------------------------------------
# Integration — /scan/passive returns easm_report
# ---------------------------------------------------------------------------

class TestEASMIntegration:
    @patch("src.app.query_ip_enrichment", new_callable=AsyncMock)
    @patch("src.app.query_email_security", new_callable=AsyncMock)
    @patch("src.app.check_breaches", new_callable=AsyncMock)
    @patch("src.app.query_wayback", new_callable=AsyncMock)
    @patch("src.app.query_rdap", new_callable=AsyncMock)
    @patch("src.app.query_ct_logs", new_callable=AsyncMock)
    @patch("src.app.query_dns", new_callable=AsyncMock)
    def test_passive_scan_includes_easm_report(
        self, mock_dns, mock_ct, mock_rdap, mock_wb, mock_breaches,
        mock_email, mock_ip,
    ):
        from src.models import ARecord, IPEnrichmentResult
        mock_dns.return_value = DNSResult(domain="example.com", a_records=[ARecord(address="93.184.216.34")])
        mock_ct.return_value = CTResult(domain="example.com")
        mock_rdap.return_value = RDAPResult(domain="example.com")
        mock_wb.return_value = WaybackResult(domain="example.com")
        mock_breaches.return_value = []
        mock_email.return_value = EmailSecurityResult(
            domain="example.com",
            spf=SPFResult(exists=True, all_qualifier="-all"),
            dmarc=DMARCResult(exists=True, policy="reject"),
            dkim=DKIMResult(selectors_found=["google"]),
            grade="A",
        )
        mock_ip.return_value = IPEnrichmentResult(domain="example.com")

        resp = client.post("/scan/passive", json={"targets": ["https://example.com"]})
        assert resp.status_code == 200
        r = resp.json()["results"][0]
        assert r["risk_assessment"]["easm_report"] is not None
        assert r["risk_assessment"]["easm_report"]["executive_summary"]["risk_posture"] in ("Low", "Moderate")
        assert r["risk_assessment"]["easm_report"]["scan_mode"] == "passive"


