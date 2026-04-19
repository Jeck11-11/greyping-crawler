"""Tests for /scan/passive and /scan/lighttouch orchestrators."""

from unittest.mock import AsyncMock, patch

import httpx

from src.models import ARecord
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
            domain="example.com", a_records=[ARecord(address="93.184.216.34")],
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

        assert len(pi["dns"]["a_records"]) == 1
        assert pi["dns"]["a_records"][0]["address"] == "93.184.216.34"
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
        # Failed source is now a typed result with .error set, not None —
        # so callers don't need to null-check every sub-field.
        assert r["passive_intel"]["ct"] is not None
        assert "crt.sh down" in r["passive_intel"]["ct"]["error"]
        assert r["passive_intel"]["dns"] is not None
        assert r["passive_intel"]["dns"]["error"] is None
        # Only a subset failed → the top-level result.error stays clean.
        assert r["error"] is None

    @patch("src.app.check_breaches", new_callable=AsyncMock)
    @patch("src.app.query_wayback", new_callable=AsyncMock)
    @patch("src.app.query_rdap", new_callable=AsyncMock)
    @patch("src.app.query_ct_logs", new_callable=AsyncMock)
    @patch("src.app.query_dns", new_callable=AsyncMock)
    def test_passive_falls_back_to_exception_class_when_message_empty(
        self, mock_dns, mock_ct, mock_rdap, mock_wb, mock_breaches,
    ):
        """Some httpx failures raise with empty args → str(exc) == ''.
        We should surface the exception class name rather than an empty
        string so operators never see a spookily-blank error field."""
        mock_dns.return_value = DNSResult(
            domain="example.com", a_records=[ARecord(address="1.2.3.4")],
        )
        mock_ct.side_effect = RuntimeError()  # no message
        mock_rdap.return_value = RDAPResult(domain="example.com")
        mock_wb.return_value = WaybackResult(domain="example.com")
        mock_breaches.return_value = []

        resp = client.post(
            "/scan/passive",
            json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        r = resp.json()["results"][0]
        assert r["passive_intel"]["ct"]["error"] == "RuntimeError"

    @patch("src.app.check_breaches", new_callable=AsyncMock)
    @patch("src.app.query_wayback", new_callable=AsyncMock)
    @patch("src.app.query_rdap", new_callable=AsyncMock)
    @patch("src.app.query_ct_logs", new_callable=AsyncMock)
    @patch("src.app.query_dns", new_callable=AsyncMock)
    def test_passive_surfaces_summary_error_when_every_source_fails(
        self, mock_dns, mock_ct, mock_rdap, mock_wb, mock_breaches,
    ):
        """Egress-blocked VPS should NOT look like a blank target."""
        mock_dns.side_effect = RuntimeError("DNS resolution timed out")
        mock_ct.side_effect = RuntimeError("crt.sh unreachable")
        mock_rdap.side_effect = RuntimeError("rdap.org unreachable")
        mock_wb.side_effect = RuntimeError("archive.org unreachable")
        mock_breaches.return_value = []

        resp = client.post(
            "/scan/passive",
            json={"targets": ["https://ibisconstruction.ie"]},
        )
        # Still 200 so batched scans aren't aborted by a broken target.
        assert resp.status_code == 200
        r = resp.json()["results"][0]
        # Every sub-source carries its own error.
        assert "DNS resolution timed out" in r["passive_intel"]["dns"]["error"]
        assert "crt.sh unreachable" in r["passive_intel"]["ct"]["error"]
        assert "rdap.org unreachable" in r["passive_intel"]["rdap"]["error"]
        assert "archive.org unreachable" in r["passive_intel"]["wayback"]["error"]
        # And the top-level result.error summarises the situation.
        assert r["error"] is not None
        assert "All passive sources failed" in r["error"]
