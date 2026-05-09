"""Tests for GitHub secret scanning module."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.github_scanner import _redact_snippet, scan_github_secrets
from src.models import GitHubSecretFinding, GitHubSecretResult


def _mock_search_response(items=None, total_count=None):
    """Build a GitHub code search API response."""
    items = items or []
    return {
        "total_count": total_count if total_count is not None else len(items),
        "incomplete_results": False,
        "items": items,
    }


def _make_item(repo="owner/repo", path=".env", html_url="https://github.com/owner/repo/blob/main/.env", fragment="DB_HOST=example.com", pushed_at="2025-01-01T00:00:00Z"):
    return {
        "name": path.split("/")[-1],
        "path": path,
        "html_url": html_url,
        "repository": {"full_name": repo, "pushed_at": pushed_at},
        "text_matches": [
            {"property": "content", "fragment": fragment, "matches": []},
        ],
    }


class TestRedactSnippet:
    def test_redacts_password(self):
        snippet = 'password = "supersecretpassword123"'
        result = _redact_snippet(snippet)
        assert "supersecretpassword123" not in result
        assert "****" in result

    def test_redacts_api_key(self):
        snippet = 'api_key: "abcdefghijklmnop1234"'
        result = _redact_snippet(snippet)
        assert "abcdefghijklmnop1234" not in result
        assert "****" in result

    def test_redacts_aws_key(self):
        snippet = "AKIAIOSFODNN7EXAMPLE"
        result = _redact_snippet(snippet)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert result.startswith("AKIA")
        assert "****" in result

    def test_preserves_non_secret_text(self):
        snippet = "# This is a comment about example.com"
        result = _redact_snippet(snippet)
        assert result == snippet

    def test_short_secret_fully_masked(self):
        snippet = 'token = "short123"'
        result = _redact_snippet(snippet)
        assert "short123" not in result


class TestScanGitHubSecrets:
    @pytest.mark.asyncio
    async def test_no_api_key(self):
        result = await scan_github_secrets("example.com", api_key="")
        assert result.error == "GITHUB_API_KEY not configured"
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_basic_results(self):
        items = [
            _make_item(repo="acme/infra", path=".env", fragment="DB_HOST=example.com\nDB_PASSWORD=hunter2"),
            _make_item(repo="acme/deploy", path="docker-compose.yml", fragment="MYSQL_HOST=example.com"),
        ]
        response = _mock_search_response(items=items, total_count=2)

        with patch("src.github_scanner.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = response
            mock_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_resp
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("src.github_scanner.asyncio.sleep", new_callable=AsyncMock):
                result = await scan_github_secrets("example.com", api_key="ghp_test123")

        assert result.error is None
        assert result.queries_run == 7
        assert len(result.findings) >= 2
        assert result.findings[0].repository == "acme/infra"
        assert result.findings[0].file_path == ".env"

    @pytest.mark.asyncio
    async def test_deduplication(self):
        """Same repo+path across different queries should be deduplicated."""
        item = _make_item(repo="acme/app", path=".env")
        response = _mock_search_response(items=[item], total_count=1)

        with patch("src.github_scanner.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = response
            mock_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_resp
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("src.github_scanner.asyncio.sleep", new_callable=AsyncMock):
                result = await scan_github_secrets("example.com", api_key="ghp_test")

        repo_paths = [(f.repository, f.file_path) for f in result.findings]
        assert len(repo_paths) == len(set(repo_paths))

    @pytest.mark.asyncio
    async def test_handles_rate_limit_403(self):
        with patch("src.github_scanner.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_resp.json.return_value = {"total_count": 0, "items": []}
            mock_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_resp
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("src.github_scanner.asyncio.sleep", new_callable=AsyncMock):
                result = await scan_github_secrets("example.com", api_key="ghp_test")

        assert result.error is None
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_handles_api_error(self):
        with patch("src.github_scanner.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.side_effect = Exception("connection refused")
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("src.github_scanner.asyncio.sleep", new_callable=AsyncMock):
                result = await scan_github_secrets("example.com", api_key="ghp_test")

        assert result.queries_run == 0
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_caps_at_50_findings(self):
        items = [
            _make_item(repo=f"org/repo-{i}", path=f"file-{i}.env")
            for i in range(60)
        ]
        response = _mock_search_response(items=items, total_count=60)

        with patch("src.github_scanner.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = response
            mock_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_resp
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("src.github_scanner.asyncio.sleep", new_callable=AsyncMock):
                result = await scan_github_secrets("example.com", api_key="ghp_test")

        assert len(result.findings) <= 50

    @pytest.mark.asyncio
    async def test_scan_duration_tracked(self):
        response = _mock_search_response()

        with patch("src.github_scanner.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = response
            mock_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_resp
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("src.github_scanner.asyncio.sleep", new_callable=AsyncMock):
                result = await scan_github_secrets("example.com", api_key="ghp_test")

        assert result.scan_duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_empty_text_matches(self):
        item = {
            "name": ".env",
            "path": ".env",
            "html_url": "https://github.com/x/y/blob/main/.env",
            "repository": {"full_name": "x/y", "pushed_at": "2025-01-01"},
            "text_matches": [],
        }
        response = _mock_search_response(items=[item], total_count=1)

        with patch("src.github_scanner.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = response
            mock_resp.raise_for_status = MagicMock()
            mock_client.get.return_value = mock_resp
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("src.github_scanner.asyncio.sleep", new_callable=AsyncMock):
                result = await scan_github_secrets("example.com", api_key="ghp_test")

        assert result.findings[0].code_snippet == ""


class TestGitHubSecretFindingFingerprint:
    def test_auto_generated(self):
        f = GitHubSecretFinding(query="env_file", repository="acme/app", file_path=".env")
        assert f.fingerprint
        assert len(f.fingerprint) == 16

    def test_stable(self):
        kwargs = dict(query="env_file", repository="acme/app", file_path=".env")
        assert GitHubSecretFinding(**kwargs).fingerprint == GitHubSecretFinding(**kwargs).fingerprint

    def test_different_repo_different_fingerprint(self):
        base = dict(query="env_file", file_path=".env")
        f1 = GitHubSecretFinding(repository="acme/app", **base)
        f2 = GitHubSecretFinding(repository="acme/other", **base)
        assert f1.fingerprint != f2.fingerprint

    def test_different_query_different_fingerprint(self):
        base = dict(repository="acme/app", file_path=".env")
        f1 = GitHubSecretFinding(query="env_file", **base)
        f2 = GitHubSecretFinding(query="password", **base)
        assert f1.fingerprint != f2.fingerprint

    def test_explicit_fingerprint_not_overwritten(self):
        f = GitHubSecretFinding(query="x", repository="y", file_path="z", fingerprint="custom")
        assert f.fingerprint == "custom"


class TestGitHubSecretsEndpoint:
    @patch("src.routers.intel.scan_github_secrets", new_callable=AsyncMock)
    def test_endpoint_returns_results(self, mock_scan):
        from fastapi.testclient import TestClient
        from src.app import app

        mock_scan.return_value = GitHubSecretResult(
            domain="example.com",
            findings=[
                GitHubSecretFinding(
                    query="env_file",
                    repository="acme/app",
                    file_path=".env",
                    file_url="https://github.com/acme/app/blob/main/.env",
                    code_snippet="DB_HOST=example.com",
                ),
            ],
            queries_run=7,
            total_matches=1,
            scan_duration_seconds=42.0,
        )

        client = TestClient(app)
        resp = client.post(
            "/recon/github-secrets",
            json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert len(body) == 1
        assert body[0]["github_secrets"]["domain"] == "example.com"
        assert len(body[0]["github_secrets"]["findings"]) == 1
        assert body[0]["github_secrets"]["findings"][0]["repository"] == "acme/app"

    @patch("src.routers.intel.scan_github_secrets", new_callable=AsyncMock)
    def test_endpoint_no_api_key(self, mock_scan):
        from fastapi.testclient import TestClient
        from src.app import app

        mock_scan.return_value = GitHubSecretResult(
            domain="example.com",
            error="GITHUB_API_KEY not configured",
        )

        client = TestClient(app)
        resp = client.post(
            "/recon/github-secrets",
            json={"targets": ["https://example.com"]},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body[0]["github_secrets"]["error"] == "GITHUB_API_KEY not configured"
