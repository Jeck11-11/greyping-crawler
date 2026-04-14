"""Tests for /recon/paths, /recon/tech, /recon/js-intel."""

from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from src.app import app
from src.models import JSIntelResult, SensitivePathFinding


client = TestClient(app)


class TestReconPaths:
    @patch("src.routers.discovery.scan_sensitive_paths", new_callable=AsyncMock)
    def test_paths_returns_findings(self, mock_scan):
        mock_scan.return_value = [
            SensitivePathFinding(
                path="/.env",
                url="https://example.com/.env",
                status_code=200,
                risk="env file exposed",
                severity="critical",
            ),
        ]
        resp = client.post(
            "/recon/paths", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()[0]
        assert body["target"] == "https://example.com"
        assert body["sensitive_paths"][0]["path"] == "/.env"


class TestReconTech:
    @patch(
        "src.routers.discovery.fetch_landing_page_full",
        new_callable=AsyncMock,
    )
    def test_tech_identifies_wordpress(self, mock_fetch):
        mock_fetch.return_value = (
            {"server": "nginx/1.18.0"},
            httpx.Cookies(),
            '<html><head><meta name="generator" content="WordPress 6.4.1">'
            '</head><body><link href="/wp-content/themes/foo.css"></body></html>',
        )
        resp = client.post(
            "/recon/tech", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()[0]
        names = {t["name"] for t in body["technologies"]}
        assert "WordPress" in names
        assert "Nginx" in names

    @patch(
        "src.routers.discovery.fetch_landing_page_full",
        new_callable=AsyncMock,
    )
    def test_tech_handles_fetch_error(self, mock_fetch):
        mock_fetch.side_effect = RuntimeError("DNS fail")
        resp = client.post(
            "/recon/tech", json={"targets": ["https://nope.invalid"]},
        )
        assert resp.status_code == 200
        body = resp.json()[0]
        assert body["technologies"] == []
        assert body["error"] == "DNS fail"


class TestReconJSIntel:
    @patch("src.routers.discovery.mine_javascript", new_callable=AsyncMock)
    @patch(
        "src.routers.discovery.fetch_landing_page_full",
        new_callable=AsyncMock,
    )
    def test_js_intel_returns_endpoints(self, mock_fetch, mock_mine):
        mock_fetch.return_value = ({}, httpx.Cookies(), "<html></html>")
        mock_mine.return_value = JSIntelResult(
            target="https://example.com",
            scripts_scanned=3,
            api_endpoints=["/api/v1/users"],
            internal_hosts=["https://admin.internal/"],
            sourcemaps_found=[],
            recovered_source_files=[],
        )
        resp = client.post(
            "/recon/js-intel", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()[0]
        assert body["scripts_scanned"] == 3
        assert body["api_endpoints"] == ["/api/v1/users"]
