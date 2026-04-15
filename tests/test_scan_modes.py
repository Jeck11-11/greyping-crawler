"""Tests for /scan/passive and /scan/lighttouch orchestrators."""

from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from src.app import app
from src.models import (
    CTResult,
    DNSResult,
    RDAPResult,
    SSLCertResult,
    WaybackResult,
)


client = TestClient(app)


# ---------------------------------------------------------------------------
# /scan/lighttouch
# ---------------------------------------------------------------------------

class TestLightTouchScan:
    @patch("src.app.fetch_landing_page_full", new_callable=AsyncMock)
    @patch("src.app.check_ssl", new_callable=AsyncMock)
    def test_lighttouch_does_one_get_and_skips_loud_probes(
        self, mock_ssl, mock_fetch,
    ):
        mock_ssl.return_value = SSLCertResult(is_valid=True, grade="A")
        html = (
            '<html><head><title>Hello</title>'
            '<meta name="generator" content="WordPress 6.4.1">'
            '</head><body>'
            '<a href="/about">About</a>'
            '<a href="https://partner.com">Partner</a>'
            'contact: hi@example.com'
            '</body></html>'
        )
        mock_fetch.return_value = (
            {"server": "nginx/1.18.0"},
            httpx.Cookies(),
            html,
        )
        resp = client.post(
            "/scan/lighttouch",
            json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        r = data["results"][0]

        # Verified: single page, no path probe, no JS mine, no breach
        assert r["pages_scanned"] == 1
        assert r["sensitive_paths"] == []
        assert r["js_intel"] is None
        assert r["breaches"] == []

        # Derived data
        tech_names = {t["name"] for t in r["technologies"]}
        assert "WordPress" in tech_names
        assert "Nginx" in tech_names
        assert r["ssl_certificate"]["grade"] == "A"
        assert r["internal_links"] == ["https://example.com/about"]
        assert any(e["email"] == "hi@example.com" for e in r["emails"])

        # Stealth flag was set
        _args, kwargs = mock_fetch.call_args
        assert kwargs.get("stealth") is True

    @patch("src.app.fetch_landing_page_full", new_callable=AsyncMock)
    @patch("src.app.check_ssl", new_callable=AsyncMock)
    def test_lighttouch_records_error_on_fetch_failure(self, mock_ssl, mock_fetch):
        mock_ssl.return_value = SSLCertResult(is_valid=True, grade="A")
        mock_fetch.return_value = ({}, httpx.Cookies(), "")  # empty body
        resp = client.post(
            "/scan/lighttouch",
            json={"targets": ["https://broken.invalid"]},
        )
        assert resp.status_code == 200
        r = resp.json()["results"][0]
        assert r["pages_scanned"] == 0
        assert r["error"] is not None


# ---------------------------------------------------------------------------
# /scan/passive
# ---------------------------------------------------------------------------

class TestPassiveScan:
    @patch("src.app.check_breaches", new_callable=AsyncMock)
    @patch("src.app.query_wayback", new_callable=AsyncMock)
    @patch("src.app.query_rdap", new_callable=AsyncMock)
    @patch("src.app.query_ct_logs", new_callable=AsyncMock)
    @patch("src.app.query_dns", new_callable=AsyncMock)
    def test_passive_aggregates_all_sources_and_touches_no_target(
        self, mock_dns, mock_ct, mock_rdap, mock_wb, mock_breaches,
    ):
        mock_dns.return_value = DNSResult(
            domain="example.com", a_records=["93.184.216.34"],
        )
        mock_ct.return_value = CTResult(
            domain="example.com",
            subdomains=["api.example.com", "admin.example.com"],
            certificates_seen=5,
        )
        mock_rdap.return_value = RDAPResult(
            domain="example.com", registrar="Example Registrar",
            created="1995-08-14", expires="2030-08-14",
        )
        mock_wb.return_value = WaybackResult(
            domain="example.com", snapshot_count=42,
        )
        mock_breaches.return_value = []

        resp = client.post(
            "/scan/passive",
            json={"targets": ["https://example.com"], "emails": []},
        )
        assert resp.status_code == 200
        r = resp.json()["results"][0]
        pi = r["passive_intel"]

        assert pi["dns"]["a_records"] == ["93.184.216.34"]
        assert pi["ct"]["certificates_seen"] == 5
        assert pi["rdap"]["registrar"] == "Example Registrar"
        assert pi["wayback"]["snapshot_count"] == 42

        # Passive mode never fetches the landing page — these fields stay default.
        assert r["pages_scanned"] == 0
        assert r["pages"] == []
        assert r["technologies"] == []
        assert r["sensitive_paths"] == []

        # Quick-glance summary counts make it through.
        assert r["summary"]["subdomains_found"] == 2
        assert r["summary"]["wayback_snapshots"] == 42

    @patch("src.app.check_breaches", new_callable=AsyncMock)
    @patch("src.app.query_wayback", new_callable=AsyncMock)
    @patch("src.app.query_rdap", new_callable=AsyncMock)
    @patch("src.app.query_ct_logs", new_callable=AsyncMock)
    @patch("src.app.query_dns", new_callable=AsyncMock)
    def test_passive_survives_individual_source_failures(
        self, mock_dns, mock_ct, mock_rdap, mock_wb, mock_breaches,
    ):
        mock_dns.return_value = DNSResult(domain="example.com")
        mock_ct.side_effect = RuntimeError("crt.sh down")
        mock_rdap.return_value = RDAPResult(domain="example.com")
        mock_wb.return_value = WaybackResult(domain="example.com")
        mock_breaches.return_value = []

        resp = client.post(
            "/scan/passive",
            json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        r = resp.json()["results"][0]
        # Failed source becomes None; other sources still present
        assert r["passive_intel"]["ct"] is None
        assert r["passive_intel"]["dns"] is not None
