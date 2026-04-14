"""Tests for /recon/ssl, /recon/headers, /recon/cookies."""

from unittest.mock import AsyncMock, patch

import httpx
from fastapi.testclient import TestClient

from src.app import app
from src.models import SSLCertResult


client = TestClient(app)


class TestReconSSL:
    @patch("src.routers.network.check_ssl", new_callable=AsyncMock)
    def test_ssl_returns_per_target_grade(self, mock_ssl):
        mock_ssl.return_value = SSLCertResult(is_valid=True, grade="A")
        resp = client.post(
            "/recon/ssl", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["target"] == "https://example.com"
        assert body[0]["ssl"]["grade"] == "A"

    def test_ssl_rejects_empty_targets(self):
        assert client.post("/recon/ssl", json={"targets": []}).status_code == 422


class TestReconHeaders:
    @patch("src.routers.network.fetch_landing_page", new_callable=AsyncMock)
    def test_headers_grades_response(self, mock_fetch):
        mock_fetch.return_value = (
            {"strict-transport-security": "max-age=63072000; includeSubDomains"},
            httpx.Cookies(),
        )
        resp = client.post(
            "/recon/headers", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["target"] == "https://example.com"
        # HSTS should contribute to a non-empty grade
        assert body[0]["headers"]["grade"] != ""


class TestReconCookies:
    @patch("src.routers.network.fetch_landing_page", new_callable=AsyncMock)
    def test_cookies_returns_findings_list(self, mock_fetch):
        mock_fetch.return_value = ({}, httpx.Cookies())
        resp = client.post(
            "/recon/cookies", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert isinstance(body[0]["cookies"], list)

    @patch("src.routers.network.fetch_landing_page", new_callable=AsyncMock)
    def test_cookies_records_error(self, mock_fetch):
        mock_fetch.side_effect = RuntimeError("boom")
        resp = client.post(
            "/recon/cookies", json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["error"] == "boom"
