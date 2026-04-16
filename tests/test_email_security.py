"""Tests for email security (SPF/DKIM/DMARC) and expanded DNS lookups."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.app import app
from src.models import (
    CTResult,
    DKIMResult,
    DMARCResult,
    DNSResult,
    DomainResult,
    EmailSecurityResult,
    MXRecord,
    PassiveIntelResult,
    RDAPResult,
    SPFResult,
    WaybackResult,
)
from src.fair_signals import compute_fair_signals
from src.passive_intel import (
    _detect_mail_providers,
    _grade_email_security,
    _parse_dmarc,
    _parse_spf,
)


client = TestClient(app)


# ---------------------------------------------------------------------------
# Unit tests — SPF parsing
# ---------------------------------------------------------------------------

class TestSPFParsing:
    def test_no_spf_record(self):
        result = _parse_spf(["some random TXT record", "another one"])
        assert result.exists is False
        assert any("No SPF" in i for i in result.issues)

    def test_spf_with_hard_fail(self):
        result = _parse_spf(["v=spf1 include:_spf.google.com -all"])
        assert result.exists is True
        assert result.all_qualifier == "-all"
        assert "_spf.google.com" in result.includes
        assert result.issues == []

    def test_spf_with_soft_fail(self):
        result = _parse_spf(["v=spf1 include:spf.protection.outlook.com ~all"])
        assert result.exists is True
        assert result.all_qualifier == "~all"
        assert result.issues == []  # ~all is acceptable

    def test_spf_with_pass_all_is_flagged(self):
        result = _parse_spf(["v=spf1 +all"])
        assert result.exists is True
        assert result.all_qualifier == "+all"
        assert any("+all" in i for i in result.issues)

    def test_spf_with_neutral_all_is_flagged(self):
        result = _parse_spf(["v=spf1 ?all"])
        assert result.all_qualifier == "?all"
        assert any("?all" in i for i in result.issues)

    def test_spf_missing_terminal_all(self):
        result = _parse_spf(["v=spf1 include:example.com"])
        assert result.exists is True
        assert result.all_qualifier is None
        assert any("terminal" in i.lower() for i in result.issues)


# ---------------------------------------------------------------------------
# Unit tests — DMARC parsing
# ---------------------------------------------------------------------------

class TestDMARCParsing:
    def test_no_dmarc_record(self):
        result = _parse_dmarc([])
        assert result.exists is False
        assert any("No DMARC" in i for i in result.issues)

    def test_dmarc_reject_with_rua(self):
        raw = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
        result = _parse_dmarc([raw])
        assert result.exists is True
        assert result.policy == "reject"
        assert len(result.rua) == 1
        assert result.issues == []

    def test_dmarc_none_policy_is_flagged(self):
        raw = "v=DMARC1; p=none; rua=mailto:dmarc@example.com"
        result = _parse_dmarc([raw])
        assert result.policy == "none"
        assert any("none" in i for i in result.issues)

    def test_dmarc_partial_pct_is_flagged(self):
        raw = "v=DMARC1; p=quarantine; pct=50; rua=mailto:d@e.com"
        result = _parse_dmarc([raw])
        assert result.pct == 50
        assert any("pct=50" in i for i in result.issues)

    def test_dmarc_no_rua_is_flagged(self):
        raw = "v=DMARC1; p=reject"
        result = _parse_dmarc([raw])
        assert result.policy == "reject"
        assert any("rua" in i for i in result.issues)

    def test_dmarc_with_subdomain_policy(self):
        raw = "v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@e.com"
        result = _parse_dmarc([raw])
        assert result.subdomain_policy == "quarantine"


# ---------------------------------------------------------------------------
# Unit tests — mail provider detection
# ---------------------------------------------------------------------------

class TestMailProviderDetection:
    def test_google_workspace_via_mx(self):
        mx = [
            MXRecord(priority=10, host="alt1.aspmx.l.google.com"),
            MXRecord(priority=1, host="aspmx.l.google.com"),
        ]
        providers = _detect_mail_providers(mx)
        assert "Google Workspace" in providers

    def test_microsoft_365_via_mx(self):
        mx = [MXRecord(priority=10, host="example-com.mail.protection.outlook.com")]
        providers = _detect_mail_providers(mx)
        assert "Microsoft 365" in providers

    def test_unknown_mx_returns_empty(self):
        mx = [MXRecord(priority=10, host="mail.custom-server.example.com")]
        providers = _detect_mail_providers(mx)
        assert providers == []


# ---------------------------------------------------------------------------
# Unit tests — grading
# ---------------------------------------------------------------------------

class TestEmailSecurityGrading:
    def test_grade_a_full_protection(self):
        spf = SPFResult(exists=True, all_qualifier="-all")
        dmarc = DMARCResult(exists=True, policy="reject")
        dkim = DKIMResult(selectors_found=["google"])
        assert _grade_email_security(spf, dmarc, dkim) == "A"

    def test_grade_f_nothing_configured(self):
        spf = SPFResult(exists=False)
        dmarc = DMARCResult(exists=False)
        dkim = DKIMResult()
        assert _grade_email_security(spf, dmarc, dkim) == "F"

    def test_grade_c_spf_soft_fail_dmarc_none(self):
        spf = SPFResult(exists=True, all_qualifier="~all")
        dmarc = DMARCResult(exists=True, policy="none")
        dkim = DKIMResult(selectors_found=["default"])
        grade = _grade_email_security(spf, dmarc, dkim)
        assert grade in ("C", "D")  # 20 + 10 + 30 = 60 → C


# ---------------------------------------------------------------------------
# Unit tests — FAIR signal integration
# ---------------------------------------------------------------------------

class TestFAIREmailSignals:
    def test_missing_email_auth_creates_vulnerability_signal(self):
        result = DomainResult(
            target="https://no-email-auth.example.com",
            passive_intel=PassiveIntelResult(
                email_security=EmailSecurityResult(
                    domain="no-email-auth.example.com",
                    spf=SPFResult(exists=False, issues=["No SPF record"]),
                    dmarc=DMARCResult(exists=False, issues=["No DMARC record"]),
                    dkim=DKIMResult(issues=["No DKIM selectors found"]),
                    grade="F",
                ),
            ),
        )
        signals = compute_fair_signals(result, scan_mode="passive")
        vuln_names = {s.name for s in signals.vulnerability.signals}
        assert "email_auth_missing" in vuln_names

    def test_strong_email_auth_creates_control_signal(self):
        result = DomainResult(
            target="https://strong-email.example.com",
            passive_intel=PassiveIntelResult(
                email_security=EmailSecurityResult(
                    domain="strong-email.example.com",
                    spf=SPFResult(exists=True, all_qualifier="-all"),
                    dmarc=DMARCResult(exists=True, policy="reject"),
                    dkim=DKIMResult(selectors_found=["google"]),
                    grade="A",
                ),
            ),
        )
        signals = compute_fair_signals(result, scan_mode="passive")
        ctrl_names = {s.name for s in signals.control_strength.signals}
        assert "email_security_posture" in ctrl_names
        # Grade A → score 95
        email_sig = next(
            s for s in signals.control_strength.signals
            if s.name == "email_security_posture"
        )
        assert email_sig.score >= 90

    def test_no_email_security_data_emits_no_signal(self):
        result = DomainResult(target="https://no-passive.example.com")
        signals = compute_fair_signals(result, scan_mode="full")
        vuln_names = {s.name for s in signals.vulnerability.signals}
        ctrl_names = {s.name for s in signals.control_strength.signals}
        assert "email_auth_missing" not in vuln_names
        assert "email_security_posture" not in ctrl_names


# ---------------------------------------------------------------------------
# Integration — /scan/passive returns email_security
# ---------------------------------------------------------------------------

class TestEmailSecurityIntegration:
    @patch("src.app.query_email_security", new_callable=AsyncMock)
    @patch("src.app.check_breaches", new_callable=AsyncMock)
    @patch("src.app.query_wayback", new_callable=AsyncMock)
    @patch("src.app.query_rdap", new_callable=AsyncMock)
    @patch("src.app.query_ct_logs", new_callable=AsyncMock)
    @patch("src.app.query_dns", new_callable=AsyncMock)
    def test_passive_scan_includes_email_security(
        self, mock_dns, mock_ct, mock_rdap, mock_wb, mock_breaches, mock_email,
    ):
        mock_dns.return_value = DNSResult(
            domain="example.com",
            a_records=["93.184.216.34"],
            mx_records=[MXRecord(priority=10, host="aspmx.l.google.com")],
        )
        mock_ct.return_value = CTResult(domain="example.com")
        mock_rdap.return_value = RDAPResult(domain="example.com")
        mock_wb.return_value = WaybackResult(domain="example.com")
        mock_breaches.return_value = []
        mock_email.return_value = EmailSecurityResult(
            domain="example.com",
            spf=SPFResult(
                raw="v=spf1 include:_spf.google.com -all",
                exists=True, all_qualifier="-all",
            ),
            dmarc=DMARCResult(
                raw="v=DMARC1; p=reject; rua=mailto:d@example.com",
                exists=True, policy="reject",
                rua=["mailto:d@example.com"],
            ),
            dkim=DKIMResult(selectors_found=["google"]),
            mail_providers=["Google Workspace"],
            grade="A",
        )

        resp = client.post(
            "/scan/passive",
            json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        r = resp.json()["results"][0]

        es = r["passive_intel"]["email_security"]
        assert es is not None
        assert es["grade"] == "A"
        assert es["spf"]["exists"] is True
        assert es["dmarc"]["policy"] == "reject"
        assert "Google Workspace" in es["mail_providers"]

        # FAIR should pick up the email signals.
        fair = r["fair_signals"]
        ctrl_names = [s["name"] for s in fair["control_strength"]["signals"]]
        assert "email_security_posture" in ctrl_names
