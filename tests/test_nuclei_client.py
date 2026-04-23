"""Tests for the Nuclei API client."""

import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.nuclei_client import _parse_jsonl_findings, run_nuclei_scan


SAMPLE_JSONL = json.dumps({
    "template-id": "cve-2021-44228",
    "info": {
        "name": "Log4j RCE",
        "severity": "critical",
        "description": "Apache Log4j2 Remote Code Execution",
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        "tags": ["cve", "rce", "log4j"],
    },
    "type": "http",
    "matched-at": "https://example.com/api",
    "extracted-results": ["${jndi:ldap://}"],
})


class TestParseJsonlFindings:
    def test_parses_single_finding(self):
        findings = _parse_jsonl_findings(SAMPLE_JSONL)
        assert len(findings) == 1
        f = findings[0]
        assert f.template_id == "cve-2021-44228"
        assert f.name == "Log4j RCE"
        assert f.severity == "critical"
        assert f.matched_at == "https://example.com/api"
        assert "cve" in f.tags

    def test_parses_multiple_lines(self):
        line2 = json.dumps({
            "template-id": "misconfig-1",
            "info": {"name": "Open Redirect", "severity": "medium"},
            "type": "http",
            "matched-at": "https://example.com/redirect",
        })
        findings = _parse_jsonl_findings(f"{SAMPLE_JSONL}\n{line2}\n")
        assert len(findings) == 2

    def test_skips_empty_and_non_json_lines(self):
        text = f"\n  \nnot json\n{SAMPLE_JSONL}\n[1,2,3]\n"
        findings = _parse_jsonl_findings(text)
        assert len(findings) == 1

    def test_empty_string_returns_empty(self):
        assert _parse_jsonl_findings("") == []


class TestRunNucleiScan:
    @pytest.mark.asyncio
    async def test_returns_error_when_not_configured(self):
        with patch("src.nuclei_client.NUCLEI_API_URL", ""):
            result = await run_nuclei_scan(["https://example.com"])
            assert result.error == "NUCLEI_API_URL not configured"
            assert result.target == "https://example.com"

    @pytest.mark.asyncio
    async def test_parses_response_stdout(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "stdout": SAMPLE_JSONL,
            "stderr": "",
            "exit_code": 0,
            "output_file": "/tmp/test.txt",
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("src.nuclei_client.NUCLEI_API_URL", "http://nuclei:8080"):
            with patch("src.nuclei_client.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.post.return_value = mock_resp
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_cls.return_value = mock_client

                result = await run_nuclei_scan(["https://example.com"])
                assert len(result.findings) == 1
                assert result.findings[0].severity == "critical"
                assert result.error == ""

    @pytest.mark.asyncio
    async def test_handles_network_error_gracefully(self):
        with patch("src.nuclei_client.NUCLEI_API_URL", "http://nuclei:8080"):
            with patch("src.nuclei_client.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.post.side_effect = Exception("Connection refused")
                mock_client.__aenter__ = AsyncMock(return_value=mock_client)
                mock_client.__aexit__ = AsyncMock(return_value=False)
                mock_cls.return_value = mock_client

                result = await run_nuclei_scan(["https://example.com"])
                assert "Connection refused" in result.error
