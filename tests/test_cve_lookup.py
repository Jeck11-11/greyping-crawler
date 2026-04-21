"""Tests for CVE correlation via osv.dev."""

import json
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.cve_lookup import lookup_cves, _extract_severity
from src.models import TechFinding


SAMPLE_OSV_RESPONSE = {
    "vulns": [
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "aliases": ["CVE-2020-11022"],
            "summary": "jQuery XSS vulnerability in htmlPrefilter",
            "severity": [
                {"type": "CVSS_V3", "score": "6.1"}
            ],
            "references": [
                {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-xxxx"},
                {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-11022"},
            ],
        }
    ]
}


class TestExtractSeverity:
    def test_cvss_v3_medium(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "6.1"}]}
        sev, score = _extract_severity(vuln)
        assert sev == "MEDIUM"
        assert score == 6.1

    def test_cvss_v3_critical(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "9.8"}]}
        sev, score = _extract_severity(vuln)
        assert sev == "CRITICAL"
        assert score == 9.8

    def test_cvss_v3_high(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "7.5"}]}
        sev, score = _extract_severity(vuln)
        assert sev == "HIGH"

    def test_cvss_v3_low(self):
        vuln = {"severity": [{"type": "CVSS_V3", "score": "2.0"}]}
        sev, score = _extract_severity(vuln)
        assert sev == "LOW"

    def test_no_severity_returns_empty(self):
        sev, score = _extract_severity({})
        assert sev == ""
        assert score is None

    def test_database_specific_fallback(self):
        vuln = {"database_specific": {"severity": "HIGH"}}
        sev, score = _extract_severity(vuln)
        assert sev == "HIGH"
        assert score is None


class TestLookupCves:
    @pytest.mark.asyncio
    async def test_skips_techs_without_version(self):
        techs = [TechFinding(name="jQuery", version=None)]
        result = await lookup_cves(techs)
        assert result == []

    @pytest.mark.asyncio
    async def test_skips_unknown_techs(self):
        techs = [TechFinding(name="UnknownFramework", version="1.0")]
        result = await lookup_cves(techs)
        assert result == []

    @pytest.mark.asyncio
    async def test_queries_osv_and_returns_findings(self):
        techs = [TechFinding(name="jQuery", version="3.3.1")]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_OSV_RESPONSE

        with patch("src.cve_lookup.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await lookup_cves(techs)
            assert len(result) == 1
            assert result[0].cve_id == "CVE-2020-11022"
            assert result[0].affected_tech == "jQuery"
            assert result[0].affected_version == "3.3.1"
            assert result[0].severity == "MEDIUM"

    @pytest.mark.asyncio
    async def test_deduplicates_findings(self):
        techs = [
            TechFinding(name="jQuery", version="3.3.1"),
            TechFinding(name="jQuery", version="3.3.1"),
        ]

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_OSV_RESPONSE

        with patch("src.cve_lookup.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await lookup_cves(techs)
            cve_ids = [f.cve_id for f in result]
            assert len(set(cve_ids)) == len(cve_ids)

    @pytest.mark.asyncio
    async def test_handles_api_error_gracefully(self):
        techs = [TechFinding(name="jQuery", version="3.3.1")]

        with patch("src.cve_lookup.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = Exception("timeout")
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_cls.return_value = mock_client

            result = await lookup_cves(techs)
            assert result == []
