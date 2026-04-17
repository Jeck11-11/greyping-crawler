"""Tests for /recon/dns, /recon/ct, /recon/whois, /recon/wayback."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from src.app import app
from src.models import CTResult, DNSResult, RDAPResult, WaybackResult


client = TestClient(app)


class TestReconDNS:
    @patch("src.routers.passive.query_dns", new_callable=AsyncMock)
    def test_dns_returns_records(self, mock_dns):
        mock_dns.return_value = DNSResult(
            domain="example.com",
            a_records=["93.184.216.34"],
            aaaa_records=["2606:2800:220:1::248"],
        )
        resp = client.post(
            "/recon/dns", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["domain"] == "example.com"
        assert body[0]["a_records"] == ["93.184.216.34"]
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
