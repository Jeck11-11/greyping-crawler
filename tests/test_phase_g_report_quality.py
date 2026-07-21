"""Phase G — EASM report-quality improvements.

top_risks/recommendations always populated, why_it_matters carries business
consequence, ransomware reconciled into the narrative, severity_breakdown +
remediation_priorities + posture_summary present, financial methodology fixed.
"""

from __future__ import annotations

from src.easm_report import build_easm_report
from src.models import (
    DomainResult,
    DNSGroup,
    DNSResult,
    EmailSecurityResult,
    DMARCResult,
    SPFResult,
    SSLCertResult,
    SecurityGroup,
    SecurityHeadersResult,
    HeaderFinding,
)


def _acme():
    return DomainResult(
        target="https://acme.ie",
        ssl=SSLCertResult(cert_valid=True, grade="A"),
        security=SecurityGroup(headers=SecurityHeadersResult(grade="D", findings=[
            HeaderFinding(header="Content-Security-Policy", status="missing", severity="medium"),
            HeaderFinding(header="Strict-Transport-Security", status="missing", severity="medium"),
        ])),
        dns=DNSGroup(
            records=DNSResult(domain="acme.ie"),
            email_security=EmailSecurityResult(
                domain="acme.ie", spf=SPFResult(exists=True),
                dmarc=DMARCResult(exists=True, policy="none"),
                grade="D", applicable=True, receives_mail=True),
        ),
    )


class TestExecutiveSummaryAlwaysActionable:
    def test_top_risks_populated_without_high_findings(self):
        rep = build_easm_report(_acme())
        # No critical/high (CSP/HSTS are medium) but top_risks must not be empty.
        assert rep.executive_summary.top_risks
        assert rep.executive_summary.recommendations

    def test_recommendations_are_fixes(self):
        rep = build_easm_report(_acme())
        assert all(isinstance(r, str) and r for r in rep.executive_summary.recommendations)


class TestWhyItMattersIsConsequence:
    def test_csp_why_differs_from_action(self):
        rep = build_easm_report(_acme())
        csp = next(f for f in rep.prioritized_findings if f.id == "missing_content_security_policy")
        assert csp.why_it_matters != csp.recommended_action
        assert "add" not in csp.why_it_matters.lower()[:6]  # not phrased as the fix


class TestRansomwareReconciled:
    def test_medium_ransomware_mentioned_in_narrative(self):
        rep = build_easm_report(_acme())
        if rep.ransomware_susceptibility.tier != "low":
            assert "ransomware" in rep.executive_summary.narrative.lower()


class TestNewRollups:
    def test_severity_breakdown(self):
        rep = build_easm_report(_acme())
        sb = rep.severity_breakdown
        assert set(sb.keys()) == {"critical", "high", "medium", "low"}
        assert sb["medium"] >= 2

    def test_remediation_priorities_ranked(self):
        rep = build_easm_report(_acme())
        rp = rep.remediation_priorities
        assert rp and rp[0].rank == 1
        assert all(rp[i].rank == i + 1 for i in range(len(rp)))
        # Customer-owned actions come first.
        assert rp[0].action

    def test_posture_summary_plain_english(self):
        rep = build_easm_report(_acme())
        ps = rep.posture_summary
        assert ps.get("TLS / Certificate") == "Strong"
        assert ps.get("Web security headers") == "Needs attention"


class TestFinancialMethodologyFixed:
    def test_no_fair_reference(self):
        rep = build_easm_report(_acme())
        assert "FAIR" not in rep.financial_impact.methodology
        assert rep.financial_impact.financial_impact_status == "insufficient_data"
