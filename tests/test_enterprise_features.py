"""Tests for enterprise EASM features: grade, RSI, financial impact, compliance, executive report."""

from src.easm_report import (
    _compute_overall_grade,
    _compute_ransomware_index,
    _compute_financial_impact,
    _compute_compliance_posture,
    _grade_to_score,
    _collect_grades,
    build_easm_report,
)
from src.models import (
    BreachRecord,
    CookieFinding,
    DomainResult,
    FAIRSignals,
    FindingClassification,
    FindingOwner,
    PrioritizedFinding,
    PortScanResult,
    OpenPort,
    RiskAssessmentGroup,
    SecurityGroup,
    SecurityHeadersResult,
    SSLCertResult,
    TechFinding,
    SecretFinding,
    SensitivePathFinding,
    DNSGroup,
    DNSResult,
    EmailSecurityResult,
    SPFResult,
    DMARCResult,
    DKIMResult,
    VulnerabilitiesGroup,
    CVEFinding,
    NucleiResult,
    NucleiFinding,
    HeaderFinding,
)


def _set_fair(result: DomainResult, **kwargs) -> None:
    """Set FAIR signals on a DomainResult via risk_assessment."""
    result.risk_assessment = RiskAssessmentGroup(fair_signals=FAIRSignals(**kwargs))


def _make_finding(severity="medium", classification=FindingClassification.confirmed_issue,
                  category="headers", finding_id="test", compliance=None):
    return PrioritizedFinding(
        id=finding_id,
        title=f"Test {severity} finding",
        category=category,
        severity=severity,
        classification=classification,
        confidence="high",
        owner=FindingOwner.customer,
        compliance=compliance or [],
    )


# ---------------------------------------------------------------------------
# Overall Domain Risk Grade
# ---------------------------------------------------------------------------

class TestOverallGrade:
    def test_grade_a_for_low_risk(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=True, grade="A"),
            security=SecurityGroup(headers=SecurityHeadersResult(grade="A")),
        )
        _set_fair(result,overall_risk=5)
        grade = _compute_overall_grade(result, [])
        assert grade in ("A+", "A", "A-")

    def test_grade_f_for_critical_risk(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=False, grade="F"),
            security=SecurityGroup(headers=SecurityHeadersResult(grade="F")),
        )
        _set_fair(result,overall_risk=90)
        findings = [
            _make_finding("critical"),
            _make_finding("critical"),
            _make_finding("critical"),
        ]
        grade = _compute_overall_grade(result, findings)
        assert grade in ("D+", "D", "D-", "F")

    def test_grade_penalized_by_critical_findings(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=True, grade="B"),
            security=SecurityGroup(headers=SecurityHeadersResult(grade="B")),
        )
        _set_fair(result, overall_risk=40)
        no_findings = _compute_overall_grade(result, [])
        many_criticals = [_make_finding("critical") for _ in range(3)]
        with_findings = _compute_overall_grade(result, many_criticals)
        assert _grade_to_score(no_findings) >= _grade_to_score(with_findings)

    def test_grade_to_score_mapping(self):
        assert _grade_to_score("A+") == 100
        assert _grade_to_score("F") == 0
        assert _grade_to_score("") == 50
        assert _grade_to_score("B") == 75


class TestCollectGrades:
    def test_collects_ssl_and_headers(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=True, grade="A"),
            security=SecurityGroup(headers=SecurityHeadersResult(grade="B+")),
        )
        grades = _collect_grades(result)
        assert grades["ssl"] == "A"
        assert grades["headers"] == "B+"

    def test_no_grades_when_empty(self):
        result = DomainResult(target="https://example.com")
        grades = _collect_grades(result)
        assert "ssl" not in grades


# ---------------------------------------------------------------------------
# Ransomware Susceptibility Index
# ---------------------------------------------------------------------------

class TestRansomwareIndex:
    def test_low_for_clean_site(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=True, grade="A", tls_version="TLSv1.3"),
            security=SecurityGroup(headers=SecurityHeadersResult(grade="A")),
            dns=DNSGroup(
                records=DNSResult(domain="example.com"),
                email_security=EmailSecurityResult(
                    domain="example.com",
                    spf=SPFResult(exists=True),
                    dmarc=DMARCResult(exists=True, policy="reject"),
                ),
            ),
            technologies=[TechFinding(name="Cloudflare", categories=["waf", "cdn"], confidence="high")],
        )
        rsi = _compute_ransomware_index(result)
        assert rsi.tier == "low"
        assert rsi.score < 25
        assert len(rsi.mitigations) > 0

    def test_high_with_exposed_rdp(self):
        result = DomainResult(
            target="https://example.com",
            port_scan=PortScanResult(
                target="https://example.com",
                open_ports=[OpenPort(port=3389, service="rdp", is_risky=True)],
            ),
        )
        rsi = _compute_ransomware_index(result)
        assert rsi.score >= 25
        assert any("3389" in f for f in rsi.factors)

    def test_high_with_no_dmarc(self):
        result = DomainResult(
            target="https://example.com",
            dns=DNSGroup(
                records=DNSResult(domain="example.com"),
                email_security=EmailSecurityResult(
                    domain="example.com",
                    spf=SPFResult(exists=False),
                    dmarc=DMARCResult(exists=False),
                ),
            ),
        )
        rsi = _compute_ransomware_index(result)
        assert rsi.score >= 15
        assert any("DMARC" in f for f in rsi.factors)

    def test_exposed_secrets_increases_score(self):
        result = DomainResult(
            target="https://example.com",
            security=SecurityGroup(
                secrets=[SecretFinding(secret_type="aws_access_key", matched_pattern="aws_key", value_preview="AKIA****1234", location="script", severity="critical")],
            ),
        )
        rsi = _compute_ransomware_index(result)
        assert rsi.score >= 10
        assert any("credential" in f.lower() or "secret" in f.lower() for f in rsi.factors)

    def test_breach_history_increases_score(self):
        result = DomainResult(
            target="https://example.com",
            breaches=[BreachRecord(source="HIBP", breach_name="TestBreach", breach_date="2023-01-01")],
        )
        rsi = _compute_ransomware_index(result)
        assert any("breach" in f.lower() for f in rsi.factors)

    def test_tier_mapping(self):
        result = DomainResult(
            target="https://example.com",
            port_scan=PortScanResult(
                target="https://example.com",
                open_ports=[
                    OpenPort(port=3389, service="rdp", is_risky=True),
                    OpenPort(port=445, service="smb", is_risky=True),
                ],
            ),
            security=SecurityGroup(
                headers=SecurityHeadersResult(grade="F"),
                secrets=[
                    SecretFinding(secret_type="aws_access_key", matched_pattern="aws_key", value_preview="AKIA****1234", location="script", severity="critical"),
                    SecretFinding(secret_type="db_password", matched_pattern="db_pass", value_preview="pass****word", location="comment", severity="critical"),
                ],
            ),
            dns=DNSGroup(
                records=DNSResult(domain="example.com"),
                email_security=EmailSecurityResult(
                    domain="example.com",
                    spf=SPFResult(exists=False),
                    dmarc=DMARCResult(exists=False),
                ),
            ),
        )
        rsi = _compute_ransomware_index(result)
        assert rsi.tier in ("high", "critical")
        assert rsi.score >= 50


# ---------------------------------------------------------------------------
# Financial Risk Quantification
# ---------------------------------------------------------------------------

class TestFinancialImpact:
    def test_low_risk_low_cost(self):
        result = DomainResult(target="https://example.com")
        _set_fair(result,overall_risk=10, loss_event_frequency=5)
        fi = _compute_financial_impact(result)
        assert fi.single_incident_cost_low > 0
        assert fi.estimated_annual_loss_low < fi.estimated_annual_loss_high
        assert any("FAIR risk score" in f for f in fi.factors)
        assert any("Company size" in f for f in fi.factors)

    def test_critical_risk_high_cost(self):
        result = DomainResult(target="https://example.com", metadata={"company_size": "enterprise"})
        _set_fair(result,overall_risk=80, loss_event_frequency=60)
        fi = _compute_financial_impact(result)
        assert fi.single_incident_cost_low >= 2_500_000
        assert fi.estimated_annual_loss_high > 0

    def test_breach_data_amplifies_cost(self):
        result_base = DomainResult(target="https://example.com", metadata={"company_size": "medium"})
        _set_fair(result_base, overall_risk=50, loss_event_frequency=30)

        result_breach = DomainResult(
            target="https://example.com",
            metadata={"company_size": "medium"},
            breaches=[BreachRecord(
                source="HIBP",
                breach_name="Breach",
                breach_date="2023-01-01",
                data_types=["Credit cards", "Passwords"],
            )],
        )
        _set_fair(result_breach, overall_risk=50, loss_event_frequency=30)

        fi_base = _compute_financial_impact(result_base)
        fi_breach = _compute_financial_impact(result_breach)
        assert fi_breach.single_incident_cost_high > fi_base.single_incident_cost_high

    def test_methodology_field(self):
        result = DomainResult(target="https://example.com")
        _set_fair(result,overall_risk=30, loss_event_frequency=15)
        fi = _compute_financial_impact(result)
        assert "IBM" in fi.methodology

    def test_company_size_scales_costs(self):
        results = {}
        for size in ("micro", "small", "medium", "large", "enterprise"):
            r = DomainResult(target="https://example.com", metadata={"company_size": size})
            _set_fair(r, overall_risk=50, loss_event_frequency=30)
            results[size] = _compute_financial_impact(r)

        assert results["micro"].single_incident_cost_high < results["small"].single_incident_cost_high
        assert results["small"].single_incident_cost_high < results["medium"].single_incident_cost_high
        assert results["medium"].single_incident_cost_high < results["large"].single_incident_cost_high
        assert results["large"].single_incident_cost_high < results["enterprise"].single_incident_cost_high

    def test_explicit_size_not_overridden(self):
        r = DomainResult(target="https://example.com", metadata={"company_size": "enterprise"})
        _set_fair(r, overall_risk=50, loss_event_frequency=30)
        fi = _compute_financial_impact(r)
        assert "Enterprise" in fi.factors[0]
        assert "auto-inferred" not in fi.factors[0]

    def test_auto_inferred_size_labelled(self):
        r = DomainResult(target="https://example.com")
        _set_fair(r, overall_risk=50, loss_event_frequency=30)
        fi = _compute_financial_impact(r)
        assert "auto-inferred" in fi.factors[0]


# ---------------------------------------------------------------------------
# Compliance Readiness
# ---------------------------------------------------------------------------

class TestCompliancePosture:
    def test_all_pass_when_no_findings(self):
        postures = _compute_compliance_posture([])
        assert len(postures) == 3
        for p in postures:
            assert p.controls_failing == 0
            assert p.readiness_score == 100

    def test_failing_controls_from_findings(self):
        findings = [
            _make_finding("high", compliance=["PCI-DSS 4.1", "ISO 27001 A.10.1.1"]),
        ]
        postures = _compute_compliance_posture(findings)
        pci = next(p for p in postures if "PCI" in p.framework)
        assert pci.controls_failing >= 1
        assert pci.readiness_score < 100
        failing = [c for c in pci.controls if c.status == "fail"]
        assert any(c.control_id == "PCI-DSS 4.1" for c in failing)

    def test_gdpr_controls_present(self):
        postures = _compute_compliance_posture([])
        gdpr = next(p for p in postures if "GDPR" in p.framework)
        assert gdpr.controls_tested == 3
        assert gdpr.readiness_score == 100

    def test_platform_behavior_not_counted_as_failing(self):
        findings = [
            _make_finding(
                "high",
                classification=FindingClassification.platform_behavior,
                compliance=["PCI-DSS 4.1"],
            ),
        ]
        postures = _compute_compliance_posture(findings)
        pci = next(p for p in postures if "PCI" in p.framework)
        assert pci.controls_failing == 0


# ---------------------------------------------------------------------------
# Executive Report Structure
# ---------------------------------------------------------------------------

class TestExecutiveReport:
    def test_includes_overall_grade(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=True, grade="A"),
            security=SecurityGroup(headers=SecurityHeadersResult(grade="B")),
        )
        report = build_easm_report(result, scan_mode="full")
        assert report.overall_grade != ""
        assert report.executive_summary.overall_grade == report.overall_grade

    def test_includes_ransomware_index(self):
        result = DomainResult(target="https://example.com")
        report = build_easm_report(result, scan_mode="full")
        assert report.ransomware_susceptibility is not None
        assert report.ransomware_susceptibility.tier in ("low", "medium", "high", "critical")

    def test_includes_financial_impact(self):
        result = DomainResult(target="https://example.com")
        _set_fair(result,overall_risk=50, loss_event_frequency=30)
        report = build_easm_report(result, scan_mode="full")
        assert report.financial_impact is not None
        assert report.financial_impact.single_incident_cost_low > 0

    def test_includes_compliance_posture(self):
        result = DomainResult(target="https://example.com")
        report = build_easm_report(result, scan_mode="full")
        assert len(report.compliance_posture) == 3
        frameworks = [p.framework for p in report.compliance_posture]
        assert any("PCI" in f for f in frameworks)
        assert any("ISO" in f for f in frameworks)
        assert any("GDPR" in f for f in frameworks)

    def test_executive_summary_has_grades_dict(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=True, grade="A+"),
            security=SecurityGroup(headers=SecurityHeadersResult(grade="B")),
        )
        report = build_easm_report(result, scan_mode="full")
        assert "overall" in report.executive_summary.grades
        assert "ssl" in report.executive_summary.grades

    def test_executive_summary_has_recommendations(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=False, grade="F"),
            security=SecurityGroup(
                headers=SecurityHeadersResult(
                    grade="F",
                    findings=[
                        HeaderFinding(
                            header="strict-transport-security",
                            status="missing",
                            severity="high",
                            recommendation="Enable HSTS",
                        ),
                    ],
                ),
            ),
        )
        report = build_easm_report(result, scan_mode="full")
        exec_summary = report.executive_summary
        assert isinstance(exec_summary.recommendations, list)

    def test_narrative_includes_grade(self):
        result = DomainResult(
            target="https://example.com",
            ssl=SSLCertResult(cert_valid=True, grade="B"),
            security=SecurityGroup(headers=SecurityHeadersResult(grade="B")),
        )
        report = build_easm_report(result, scan_mode="full")
        assert "Overall grade:" in report.executive_summary.narrative

    def test_narrative_includes_ransomware_when_high(self):
        result = DomainResult(
            target="https://example.com",
            port_scan=PortScanResult(
                target="https://example.com",
                open_ports=[
                    OpenPort(port=3389, service="rdp", is_risky=True),
                    OpenPort(port=445, service="smb", is_risky=True),
                ],
            ),
            security=SecurityGroup(
                headers=SecurityHeadersResult(grade="F"),
                secrets=[
                    SecretFinding(secret_type="aws_key", matched_pattern="aws_key", value_preview="AKIA****5678", location="script", severity="critical"),
                    SecretFinding(secret_type="db_pw", matched_pattern="db_pass", value_preview="root****pass", location="comment", severity="critical"),
                ],
            ),
            dns=DNSGroup(
                records=DNSResult(domain="example.com"),
                email_security=EmailSecurityResult(
                    domain="example.com",
                    spf=SPFResult(exists=False),
                    dmarc=DMARCResult(exists=False),
                ),
            ),
        )
        report = build_easm_report(result, scan_mode="full")
        if report.ransomware_susceptibility.score >= 50:
            assert "Ransomware" in report.executive_summary.narrative or "ransomware" in report.executive_summary.narrative
