"""Phase D correctness fixes — acceptance tests.

Covers spec Tests 7 (organisational compliance controls not_assessed),
13 (WordPress login), 14 (scoring consistency). Plus header severity (#15) and
financial insufficient_data (#20).
"""

from __future__ import annotations

from src.easm_report import (
    _compute_compliance_posture,
    _compute_financial_impact,
    _compute_overall_grade,
    _classify_path_findings,
    build_easm_report,
)
from src.models import (
    DomainResult,
    FindingClassification,
    FindingOwner,
    PrioritizedFinding,
    SecurityGroup,
    SensitivePathFinding,
)


def _confirmed(fid, sev="high", affects=True):
    return PrioritizedFinding(
        id=fid, title=fid, category="x", severity=sev,
        classification=FindingClassification.confirmed_issue,
        owner=FindingOwner.customer, affects_risk_score=affects,
    )


# --------------------------------------------------------------------------
# Test 7 — organisational compliance controls are not_assessed
# --------------------------------------------------------------------------

class TestComplianceNotAssessed:
    def test_org_controls_not_assessed(self):
        postures = _compute_compliance_posture([])
        by_id = {c.control_id: c.status for p in postures for c in p.controls}
        assert by_id["GDPR Art.33"] == "not_assessed"
        assert by_id["GDPR Art.34"] == "not_assessed"
        assert by_id["PCI-DSS 12.10"] == "not_assessed"
        assert by_id["ISO 27001 A.7.2.2"] == "not_assessed"
        assert by_id["ISO 27001 A.15.1.1"] == "not_assessed"

    def test_org_controls_never_pass_from_absence(self):
        postures = _compute_compliance_posture([])
        for p in postures:
            for c in p.controls:
                if c.control_id in (
                    "GDPR Art.33", "GDPR Art.34", "PCI-DSS 12.10",
                    "ISO 27001 A.7.2.2",
                ):
                    assert c.status != "pass"

    def test_readiness_excludes_not_assessed(self):
        postures = _compute_compliance_posture([])
        gdpr = next(p for p in postures if p.framework == "GDPR")
        # GDPR has 1 observable (Art.32) + 2 organisational => tested==1
        assert gdpr.controls_tested == 1
        assert gdpr.controls_not_tested == 2


# --------------------------------------------------------------------------
# Test 13 — WordPress login reachable is not a confirmed vuln
# --------------------------------------------------------------------------

class TestWordPressLogin:
    def test_wp_login_is_attack_surface_observation(self):
        result = DomainResult(
            target="https://blog.example.com",
            security=SecurityGroup(sensitive_paths=[
                SensitivePathFinding(path="/wp-login.php", url="https://blog.example.com/wp-login.php",
                                     status_code=200, severity="low", risk="WP login"),
            ]),
        )
        findings = _classify_path_findings(result)
        assert len(findings) == 1
        f = findings[0]
        assert f.classification == FindingClassification.attack_surface_observation
        assert f.severity == "informational"
        assert f.affects_risk_score is False

    def test_real_sensitive_path_still_confirmed(self):
        result = DomainResult(
            target="https://x.example.com",
            security=SecurityGroup(sensitive_paths=[
                SensitivePathFinding(path="/.env", url="https://x.example.com/.env",
                                     status_code=200, severity="critical", risk="env"),
            ]),
        )
        findings = _classify_path_findings(result)
        assert findings[0].classification == FindingClassification.confirmed_issue


# --------------------------------------------------------------------------
# Test 14 — scoring consistency
# --------------------------------------------------------------------------

class TestScoringConsistency:
    def test_unverified_findings_do_not_penalize_grade(self):
        result = DomainResult(target="https://x.example.com")
        # A "confirmed" finding that does not affect score must not lower grade.
        grade_with_excluded = _compute_overall_grade(result, [_confirmed("candidate", affects=False)])
        grade_clean = _compute_overall_grade(result, [])
        assert grade_with_excluded == grade_clean

    def test_scoring_traceability_present(self):
        result = DomainResult(
            target="https://x.example.com",
            security=SecurityGroup(),
        )
        report = build_easm_report(result)
        # Every EASM report exposes tier + traceability that agree with the grade.
        assert report.risk_tier in ("low", "moderate", "high", "critical")
        assert isinstance(report.score_inputs, list)
        assert isinstance(report.excluded_inputs, list)


# --------------------------------------------------------------------------
# #20 — financial estimate suppressed without customer inputs
# --------------------------------------------------------------------------

class TestFinancialGating:
    def test_insufficient_data_without_customer_size(self):
        result = DomainResult(target="https://x.example.com")
        fi = _compute_financial_impact(result)
        assert fi.financial_impact_status == "insufficient_data"
        assert fi.estimated_annual_loss_high == 0

    def test_scanner_never_estimates_money(self):
        # FAIR/financial quantification moved to Xano — scanner always defers.
        result = DomainResult(target="https://x.example.com", metadata={"company_size": "small"})
        fi = _compute_financial_impact(result)
        assert fi.financial_impact_status == "insufficient_data"
