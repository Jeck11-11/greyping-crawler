"""Tests for the FastAPI OSINT API endpoints."""

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from src.app import app
from src.models import ContactInfo, DomainResult, PageResult


client = TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_ok(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestScanEndpoint:
    @patch("src.app.crawl_domain", new_callable=AsyncMock)
    @patch("src.app.check_breaches", new_callable=AsyncMock)
    def test_scan_returns_structured_response(self, mock_breaches, mock_crawl):
        mock_crawl.return_value = [
            PageResult(
                url="https://example.com",
                status_code=200,
                title="Example",
                contacts=ContactInfo(emails=["a@example.com"]),
                links=[],
                secrets=[],
            )
        ]
        mock_breaches.return_value = []

        resp = client.post("/scan", json={
            "targets": ["https://example.com"],
            "render_js": False,
            "max_depth": 0,
            "check_breaches": False,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "scan_id" in data
        assert data["total_targets"] == 1
        assert data["status"] == "completed"
        assert len(data["results"]) == 1
        assert data["results"][0]["target"] == "https://example.com"

    @patch("src.app.crawl_domain", new_callable=AsyncMock)
    def test_scan_multiple_targets(self, mock_crawl):
        mock_crawl.return_value = [
            PageResult(url="https://a.com", status_code=200)
        ]

        resp = client.post("/scan", json={
            "targets": ["https://a.com", "https://b.com"],
            "render_js": False,
            "max_depth": 0,
            "check_breaches": False,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_targets"] == 2
        assert len(data["results"]) == 2

    def test_scan_rejects_empty_targets(self):
        resp = client.post("/scan", json={"targets": []})
        assert resp.status_code == 422

    def test_scan_rejects_missing_targets(self):
        resp = client.post("/scan", json={})
        assert resp.status_code == 422


class TestQuickScanEndpoint:
    @patch("src.app.crawl_domain", new_callable=AsyncMock)
    def test_quick_scan_overrides_options(self, mock_crawl):
        mock_crawl.return_value = [
            PageResult(url="https://example.com", status_code=200)
        ]

        resp = client.post("/scan/quick", json={
            "targets": ["https://example.com"],
        })
        assert resp.status_code == 200

        # Verify crawl was called with render_js=False and max_depth=0
        call_kwargs = mock_crawl.call_args
        assert call_kwargs.kwargs["render_js"] is False
        assert call_kwargs.kwargs["max_depth"] == 0
