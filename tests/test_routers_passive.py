"""Tests for /recon/dns, /recon/ct, /recon/whois, /recon/wayback, /recon/email-security."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.app import app
from src.models import (
    ARecord,
    AAAARecord,
    CTResult,
    DKIMResult,
    DMARCResult,
    DNSResult,
    EmailSecurityResult,
    RDAPResult,
    SPFResult,
    WaybackResult,
)


client = TestClient(app)


class TestReconDNS:
    @patch("src.routers.passive.query_dns", new_callable=AsyncMock)
    def test_dns_returns_records(self, mock_dns):
        mock_dns.return_value = DNSResult(
            domain="example.com",
            a_records=[ARecord(address="93.184.216.34", ttl=3600, reverse="example.com")],
            aaaa_records=[AAAARecord(address="2606:2800:220:1::248", ttl=3600, reverse="")],
        )
        resp = client.post(
            "/recon/dns", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["domain"] == "example.com"
        assert len(body[0]["a_records"]) == 1
        assert body[0]["a_records"][0]["address"] == "93.184.216.34"
        args, _ = mock_dns.call_args
        assert args[0] == "example.com"   # normalised: no scheme, no www


class TestReconCT:
    @patch("src.routers.passive.query_ct_logs", new_callable=AsyncMock)
    def test_ct_returns_subdomains(self, mock_ct):
        mock_ct.return_value = CTResult(
            domain="example.com",
            subdomains=["api.example.com", "example.com"],
            issuers=["Let's Encrypt"],
            certificates_seen=42,
        )
        resp = client.post(
            "/recon/ct", json={"targets": ["https://www.example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["certificates_seen"] == 42
        assert "api.example.com" in body[0]["subdomains"]


class TestReconWhois:
    @patch("src.routers.passive.query_rdap", new_callable=AsyncMock)
    def test_whois_returns_registrar(self, mock_rdap):
        mock_rdap.return_value = RDAPResult(
            domain="example.com",
            registrar="Example Registrar Inc.",
            created="1995-08-14",
            expires="2030-08-14",
        )
        resp = client.post(
            "/recon/whois", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["registrar"] == "Example Registrar Inc."


class TestReconWayback:
    @patch("src.routers.passive.query_wayback", new_callable=AsyncMock)
    def test_wayback_returns_snapshot_count(self, mock_wb):
        mock_wb.return_value = WaybackResult(
            domain="example.com",
            snapshot_count=17,
            first_seen="2001-01-01",
            last_seen="2024-01-01",
        )
        resp = client.post(
            "/recon/wayback", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["snapshot_count"] == 17


class TestReconEmailSecurity:
    @patch("src.routers.passive.query_email_security", new_callable=AsyncMock)
    @patch("src.routers.passive.query_dns", new_callable=AsyncMock)
    def test_email_security_returns_spf_dmarc_dkim(self, mock_dns, mock_email):
        mock_dns.return_value = DNSResult(
            domain="example.com",
            mx_records=[],
        )
        mock_email.return_value = EmailSecurityResult(
            domain="example.com",
            spf=SPFResult(
                raw="v=spf1 include:_spf.google.com -all",
                exists=True,
                all_qualifier="-all",
            ),
            dmarc=DMARCResult(
                raw="v=DMARC1; p=reject; rua=mailto:d@example.com",
                exists=True,
                policy="reject",
                rua=["mailto:d@example.com"],
            ),
            dkim=DKIMResult(selectors_found=["google"]),
            grade="A",
        )
        resp = client.post(
            "/recon/email-security", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["domain"] == "example.com"
        assert body[0]["spf"]["exists"] is True
        assert body[0]["spf"]["all_qualifier"] == "-all"
        assert body[0]["dmarc"]["policy"] == "reject"
        assert body[0]["dkim"]["selectors_found"] == ["google"]
        assert body[0]["grade"] == "A"

    @patch("src.routers.passive.query_email_security", new_callable=AsyncMock)
    @patch("src.routers.passive.query_dns", new_callable=AsyncMock)
    def test_email_security_handles_failure(self, mock_dns, mock_email):
        mock_dns.side_effect = RuntimeError("DNS lookup failed")
        resp = client.post(
            "/recon/email-security", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["domain"] == "example.com"
        assert body[0]["error"] is not None
        assert "DNS lookup failed" in body[0]["error"]
