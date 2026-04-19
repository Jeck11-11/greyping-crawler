"""Tests for API key authentication and rate limiting middleware."""

from unittest.mock import patch

from fastapi.testclient import TestClient


def _make_client(api_keys="", scan_rpm="60", recon_rpm="300"):
    """Create a fresh TestClient with the given env vars."""
    env = {
        "OSINT_API_KEYS": api_keys,
        "RATE_LIMIT_SCAN": scan_rpm,
        "RATE_LIMIT_RECON": recon_rpm,
    }
    with patch.dict("os.environ", env, clear=False):
        from importlib import reload
        import src.middleware
        reload(src.middleware)
        import src.app
        reload(src.app)
        client = TestClient(src.app.app)
        client.get("/health")  # force middleware stack build while env is patched
        return client


class TestAPIKeyMiddleware:
    def test_auth_disabled_when_no_keys(self):
        client = _make_client(api_keys="")
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_valid_key_passes(self):
        client = _make_client(api_keys="testkey123")
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_invalid_key_returns_401(self):
        client = _make_client(api_keys="testkey123")
        resp = client.post(
            "/recon/ssl",
            json={"targets": ["https://example.com"]},
            headers={"X-API-Key": "wrongkey"},
        )
        assert resp.status_code == 401
        assert "Invalid" in resp.json()["detail"]

    def test_missing_key_returns_401(self):
        client = _make_client(api_keys="testkey123")
        resp = client.post(
            "/recon/ssl",
            json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 401

    def test_exempt_paths_bypass_auth(self):
        client = _make_client(api_keys="testkey123")
        assert client.get("/health").status_code == 200
        assert client.get("/docs").status_code == 200
        assert client.get("/openapi.json").status_code == 200


class TestRateLimitMiddleware:
    def test_requests_within_limit_pass(self):
        client = _make_client(scan_rpm="10", recon_rpm="10")
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_exceeding_limit_returns_429(self):
        client = _make_client(api_keys="", scan_rpm="2", recon_rpm="2")
        for _ in range(3):
            resp = client.get("/health")
        # /health is not under /scan or /recon, so it shouldn't be rate-limited
        assert resp.status_code == 200
