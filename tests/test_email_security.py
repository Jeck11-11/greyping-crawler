"""Tests for email security (SPF/DKIM/DMARC) and expanded DNS lookups."""

import pytest
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.app import app
from src.models import (
    CTResult,
    DKIMResult,
    DMARCResult,
    DNSGroup,
    DNSResult,
    DomainResult,
    EmailSecurityResult,
    MXRecord,
    PassiveIntelSlim,
    RDAPResult,
    SPFIntelResult,
    SPFResult,
    SPFSenderInfo,
    WaybackResult,
)
from src.fair_signals import compute_fair_signals
from src.passive_intel import (
    _detect_mail_providers,
    _grade_email_security,
    _map_include_to_service,
    _parse_dmarc,
    _parse_spf,
    _parse_spf_mechanisms,
    enumerate_spf,
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
            dns=DNSGroup(email_security=EmailSecurityResult(
                domain="no-email-auth.example.com",
                spf=SPFResult(exists=False, issues=["No SPF record"]),
                dmarc=DMARCResult(exists=False, issues=["No DMARC record"]),
                dkim=DKIMResult(issues=["No DKIM selectors found"]),
                grade="F",
            )),
        )
        signals = compute_fair_signals(result, scan_mode="passive")
        vuln_names = {s.name for s in signals.vulnerability.signals}
        assert "email_auth_missing" in vuln_names

    def test_strong_email_auth_creates_control_signal(self):
        result = DomainResult(
            target="https://strong-email.example.com",
            dns=DNSGroup(email_security=EmailSecurityResult(
                domain="strong-email.example.com",
                spf=SPFResult(exists=True, all_qualifier="-all"),
                dmarc=DMARCResult(exists=True, policy="reject"),
                dkim=DKIMResult(selectors_found=["google"]),
                grade="A",
            )),
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
        from src.models import ARecord, MXRecordFull
        mock_dns.return_value = DNSResult(
            domain="example.com",
            a_records=[ARecord(address="93.184.216.34")],
            mx_records=[MXRecordFull(priority=10, host="aspmx.l.google.com")],
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

        es = r["dns"]["email_security"]
        assert es is not None
        assert es["grade"] == "A"
        assert es["spf"]["exists"] is True
        assert es["dmarc"]["policy"] == "reject"
        assert "Google Workspace" in es["mail_providers"]

        # FAIR should pick up the email signals.
        fair = r["risk_assessment"]["fair_signals"]
        ctrl_names = [s["name"] for s in fair["control_strength"]["signals"]]
        assert "email_security_posture" in ctrl_names


# ---------------------------------------------------------------------------
# Unit tests — SPF mechanism parsing
# ---------------------------------------------------------------------------

class TestSPFMechanismParsing:
    def test_ip4_mechanisms(self):
        mechs = _parse_spf_mechanisms("v=spf1 ip4:192.168.1.0/24 ip4:10.0.0.1 -all")
        ip4s = [m for m in mechs if m.mechanism == "ip4"]
        assert len(ip4s) == 2
        assert ip4s[0].value == "192.168.1.0/24"
        assert ip4s[1].value == "10.0.0.1"

    def test_ip6_mechanisms(self):
        mechs = _parse_spf_mechanisms("v=spf1 ip6:2001:db8::/32 -all")
        ip6s = [m for m in mechs if m.mechanism == "ip6"]
        assert len(ip6s) == 1
        assert ip6s[0].value == "2001:db8::/32"

    def test_include_mechanisms(self):
        mechs = _parse_spf_mechanisms("v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all")
        includes = [m for m in mechs if m.mechanism == "include"]
        assert len(includes) == 2
        assert includes[0].value == "_spf.google.com"
        assert includes[1].value == "spf.protection.outlook.com"

    def test_redirect(self):
        mechs = _parse_spf_mechanisms("v=spf1 redirect=_spf.example.com")
        redirects = [m for m in mechs if m.mechanism == "redirect"]
        assert len(redirects) == 1
        assert redirects[0].value == "_spf.example.com"

    def test_a_and_mx_mechanisms(self):
        mechs = _parse_spf_mechanisms("v=spf1 a mx -all")
        assert any(m.mechanism == "a" for m in mechs)
        assert any(m.mechanism == "mx" for m in mechs)

    def test_qualifiers(self):
        mechs = _parse_spf_mechanisms("v=spf1 +a -mx ~ip4:10.0.0.1 ?all")
        a_mech = next(m for m in mechs if m.mechanism == "a")
        assert a_mech.qualifier == "+"
        mx_mech = next(m for m in mechs if m.mechanism == "mx")
        assert mx_mech.qualifier == "-"
        ip4_mech = next(m for m in mechs if m.mechanism == "ip4")
        assert ip4_mech.qualifier == "~"

    def test_empty_record(self):
        mechs = _parse_spf_mechanisms("v=spf1")
        assert mechs == []

    def test_complex_real_world_spf(self):
        raw = "v=spf1 ip4:198.51.100.0/24 include:_spf.google.com include:servers.mcsv.net a mx ~all"
        mechs = _parse_spf_mechanisms(raw)
        types = [m.mechanism for m in mechs]
        assert "ip4" in types
        assert "include" in types
        assert "a" in types
        assert "mx" in types
        assert "all" in types


# ---------------------------------------------------------------------------
# Unit tests — SPF include service mapping
# ---------------------------------------------------------------------------

class TestSPFServiceMapping:
    def test_google_workspace(self):
        assert _map_include_to_service("_spf.google.com") == "Google Workspace"

    def test_microsoft_365(self):
        assert _map_include_to_service("spf.protection.outlook.com") == "Microsoft 365"

    def test_sendgrid(self):
        assert _map_include_to_service("sendgrid.net") == "SendGrid"

    def test_mailchimp(self):
        assert _map_include_to_service("servers.mcsv.net") == "Mailchimp"

    def test_amazon_ses(self):
        assert _map_include_to_service("amazonses.com") == "Amazon SES"

    def test_hubspot(self):
        assert _map_include_to_service("spf1.hubspot.com") == "HubSpot"

    def test_zendesk(self):
        assert _map_include_to_service("mail.zendesk.com") == "Zendesk"

    def test_unknown_domain(self):
        assert _map_include_to_service("custom.mailserver.example.com") == ""


# ---------------------------------------------------------------------------
# Unit tests — SPF enumeration (mocked DNS)
# ---------------------------------------------------------------------------

class TestEnumerateSPF:
    @pytest.mark.asyncio
    async def test_no_spf_returns_empty(self):
        spf = SPFResult(exists=False)
        result = await enumerate_spf("example.com", spf)
        assert result.domain == "example.com"
        assert result.mechanisms == []
        assert result.senders == []

    @pytest.mark.asyncio
    async def test_ip4_only_record(self):
        spf = SPFResult(
            exists=True,
            raw="v=spf1 ip4:198.51.100.0/24 ip4:203.0.113.5 -all",
        )
        with patch("src.passive_intel._resolve_spf_record", return_value=None):
            with patch("src.passive_intel._cymru_origin_lookup", return_value="13335 | 198.51.100.0/24 | US | arin | 2010-01-01"):
                with patch("src.passive_intel._cymru_asn_lookup", return_value="13335 | US | arin | 2010-01-01 | CLOUDFLARENET, US"):
                    result = await enumerate_spf("example.com", spf)

        assert len(result.ip4_ranges) == 2
        assert "198.51.100.0/24" in result.ip4_ranges
        assert "203.0.113.5" in result.ip4_ranges
        assert len(result.senders) == 2

    @pytest.mark.asyncio
    async def test_include_service_detection(self):
        spf = SPFResult(
            exists=True,
            raw="v=spf1 include:_spf.google.com include:sendgrid.net -all",
            includes=["_spf.google.com", "sendgrid.net"],
        )
        google_spf = "v=spf1 ip4:35.190.247.0/24 ~all"
        sendgrid_spf = "v=spf1 ip4:167.89.0.0/17 ~all"

        def mock_resolve(domain):
            if "google" in domain:
                return google_spf
            if "sendgrid" in domain:
                return sendgrid_spf
            return None

        with patch("src.passive_intel._resolve_spf_record", side_effect=mock_resolve):
            with patch("src.passive_intel._cymru_origin_lookup", return_value=None):
                result = await enumerate_spf("example.com", spf)

        assert "Google Workspace" in result.services_detected
        assert "SendGrid" in result.services_detected
        assert "35.190.247.0/24" in result.ip4_ranges
        assert "167.89.0.0/17" in result.ip4_ranges

    @pytest.mark.asyncio
    async def test_dns_lookup_counting(self):
        spf = SPFResult(
            exists=True,
            raw="v=spf1 include:a.com include:b.com include:c.com include:d.com a mx -all",
            includes=["a.com", "b.com", "c.com", "d.com"],
        )

        counter = [0]
        def mock_resolve(domain):
            counter[0] += 1
            suffix = counter[0]
            return f"v=spf1 ip4:10.0.0.{suffix} include:child{suffix}a.com include:child{suffix}b.com -all"

        with patch("src.passive_intel._resolve_spf_record", side_effect=mock_resolve):
            with patch("src.passive_intel._cymru_origin_lookup", return_value=None):
                result = await enumerate_spf("example.com", spf)

        assert result.dns_lookup_count > 10
        assert result.exceeds_lookup_limit is True

    @pytest.mark.asyncio
    async def test_redirect_mechanism(self):
        spf = SPFResult(
            exists=True,
            raw="v=spf1 redirect=_spf.example.com",
        )
        redirect_spf = "v=spf1 ip4:192.0.2.0/24 -all"

        def mock_resolve(domain):
            if domain == "_spf.example.com":
                return redirect_spf
            return None

        with patch("src.passive_intel._resolve_spf_record", side_effect=mock_resolve):
            with patch("src.passive_intel._cymru_origin_lookup", return_value=None):
                result = await enumerate_spf("example.com", spf)

        assert "192.0.2.0/24" in result.ip4_ranges
        assert len(result.include_tree) == 1

    @pytest.mark.asyncio
    async def test_ip_enrichment(self):
        spf = SPFResult(
            exists=True,
            raw="v=spf1 ip4:198.51.100.1 -all",
        )
        with patch("src.passive_intel._cymru_origin_lookup", return_value="15169 | 198.51.100.0/24 | US | arin | 2012"):
            with patch("src.passive_intel._cymru_asn_lookup", return_value="15169 | US | arin | 2012-01-01 | GOOGLE, US"):
                result = await enumerate_spf("example.com", spf)

        assert len(result.senders) == 1
        sender = result.senders[0]
        assert sender.ip == "198.51.100.1"
        assert sender.asn == 15169
        assert "GOOGLE" in sender.asn_name
        assert sender.country_code == "US"
        assert sender.provider == "Google Cloud"

    @pytest.mark.asyncio
    async def test_handles_dns_failure_gracefully(self):
        spf = SPFResult(
            exists=True,
            raw="v=spf1 include:broken.example.com -all",
            includes=["broken.example.com"],
        )
        with patch("src.passive_intel._resolve_spf_record", return_value=None):
            result = await enumerate_spf("example.com", spf)

        assert result.error is None
        assert len(result.include_tree) == 1
        assert result.include_tree[0].error is not None

    @pytest.mark.asyncio
    async def test_ipv6_ranges_collected(self):
        spf = SPFResult(
            exists=True,
            raw="v=spf1 ip6:2001:db8::/32 ip4:10.0.0.1 -all",
        )
        with patch("src.passive_intel._cymru_origin_lookup", return_value=None):
            result = await enumerate_spf("example.com", spf)

        assert "2001:db8::/32" in result.ip6_ranges
        assert "10.0.0.1" in result.ip4_ranges


# ---------------------------------------------------------------------------
# FAIR signal — SPF lookup limit exceeded
# ---------------------------------------------------------------------------

class TestFAIRSPFLookupLimit:
    def test_exceeds_limit_fires_signal(self):
        result = DomainResult(
            target="https://example.com",
            dns=DNSGroup(email_security=EmailSecurityResult(
                domain="example.com",
                spf=SPFResult(
                    exists=True,
                    raw="v=spf1 include:a include:b -all",
                    intel=SPFIntelResult(
                        domain="example.com",
                        dns_lookup_count=14,
                        exceeds_lookup_limit=True,
                    ),
                ),
                grade="C",
            )),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        vuln_names = [s.name for s in signals.vulnerability.signals]
        assert "spf_lookup_limit_exceeded" in vuln_names

        sig = next(s for s in signals.vulnerability.signals if s.name == "spf_lookup_limit_exceeded")
        assert sig.score == 65
        assert "14" in sig.evidence[0]

    def test_under_limit_no_signal(self):
        result = DomainResult(
            target="https://example.com",
            dns=DNSGroup(email_security=EmailSecurityResult(
                domain="example.com",
                spf=SPFResult(
                    exists=True,
                    raw="v=spf1 include:a -all",
                    intel=SPFIntelResult(
                        domain="example.com",
                        dns_lookup_count=5,
                        exceeds_lookup_limit=False,
                    ),
                ),
                grade="B",
            )),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        vuln_names = [s.name for s in signals.vulnerability.signals]
        assert "spf_lookup_limit_exceeded" not in vuln_names

    def test_no_intel_no_signal(self):
        result = DomainResult(
            target="https://example.com",
            dns=DNSGroup(email_security=EmailSecurityResult(
                domain="example.com",
                spf=SPFResult(exists=True, raw="v=spf1 -all"),
                grade="A",
            )),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        vuln_names = [s.name for s in signals.vulnerability.signals]
        assert "spf_lookup_limit_exceeded" not in vuln_names
