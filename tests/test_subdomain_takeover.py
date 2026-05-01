"""Tests for subdomain_takeover module."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest

from src.subdomain_takeover import (
    SUBDOMAIN_WORDLIST,
    TAKEOVER_SERVICES,
    _check_cname_dangling,
    _match_service,
    _resolve_subdomain,
    _verify_http,
    check_takeovers,
    enumerate_subdomains,
    scan_subdomain_takeover,
)


# ---------------------------------------------------------------------------
# Fingerprint database sanity checks
# ---------------------------------------------------------------------------

class TestTakeoverServices:
    def test_services_not_empty(self):
        assert len(TAKEOVER_SERVICES) >= 20

    def test_each_service_has_required_keys(self):
        for name, info in TAKEOVER_SERVICES.items():
            assert "cnames" in info, f"{name} missing 'cnames'"
            assert "http_fingerprints" in info, f"{name} missing 'http_fingerprints'"
            assert "severity" in info, f"{name} missing 'severity'"
            assert info["severity"] in ("critical", "high", "medium", "low", "info"), (
                f"{name} has invalid severity: {info['severity']}"
            )

    def test_cname_patterns_start_with_dot(self):
        for name, info in TAKEOVER_SERVICES.items():
            for pattern in info["cnames"]:
                assert pattern.startswith(".") or "." in pattern, (
                    f"{name} cname pattern '{pattern}' looks wrong"
                )


class TestWordlist:
    def test_wordlist_not_empty(self):
        assert len(SUBDOMAIN_WORDLIST) >= 100

    def test_no_dots_in_prefixes(self):
        for prefix in SUBDOMAIN_WORDLIST:
            assert "." not in prefix, f"Prefix '{prefix}' shouldn't contain a dot"

    def test_common_prefixes_present(self):
        for expected in ("api", "dev", "staging", "admin", "mail", "vpn", "cdn"):
            assert expected in SUBDOMAIN_WORDLIST, f"'{expected}' missing from wordlist"


# ---------------------------------------------------------------------------
# _match_service
# ---------------------------------------------------------------------------

class TestMatchService:
    def test_github_pages(self):
        result = _match_service("user.github.io")
        assert result is not None
        assert result[0] == "GitHub Pages"

    def test_s3_bucket(self):
        result = _match_service("mybucket.s3.amazonaws.com")
        assert result is not None
        assert result[0] == "Amazon S3"

    def test_heroku(self):
        result = _match_service("myapp.herokuapp.com")
        assert result is not None
        assert result[0] == "Heroku"

    def test_azure_web(self):
        result = _match_service("mysite.azurewebsites.net")
        assert result is not None
        assert result[0] == "Azure Web Apps"

    def test_vercel(self):
        result = _match_service("myapp.vercel.app")
        assert result is not None
        assert result[0] == "Vercel"

    def test_netlify(self):
        result = _match_service("mysite.netlify.app")
        assert result is not None
        assert result[0] == "Netlify"

    def test_no_match(self):
        result = _match_service("example.com")
        assert result is None

    def test_case_insensitive(self):
        result = _match_service("MyApp.HEROKUAPP.COM")
        assert result is not None
        assert result[0] == "Heroku"


# ---------------------------------------------------------------------------
# _check_cname_dangling
# ---------------------------------------------------------------------------

class TestCheckCnameDangling:
    @pytest.mark.asyncio
    async def test_dangling_returns_true(self):
        with patch("src.subdomain_takeover.dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.resolver.NXDOMAIN()
            assert await _check_cname_dangling("dead.example.com") is True

    @pytest.mark.asyncio
    async def test_alive_returns_false(self):
        with patch("src.subdomain_takeover.dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            mock_answer = MagicMock()
            instance.resolve.return_value = mock_answer
            assert await _check_cname_dangling("alive.example.com") is False

    @pytest.mark.asyncio
    async def test_error_returns_false(self):
        with patch("src.subdomain_takeover.dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = Exception("network error")
            assert await _check_cname_dangling("error.example.com") is False


# ---------------------------------------------------------------------------
# _resolve_subdomain
# ---------------------------------------------------------------------------

class TestResolveSubdomain:
    @pytest.mark.asyncio
    async def test_returns_none_for_nxdomain(self):
        with patch("src.subdomain_takeover.dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value
            instance.resolve.side_effect = dns.resolver.NXDOMAIN()
            result = await _resolve_subdomain("dead.example.com")
            assert result is None

    @pytest.mark.asyncio
    async def test_returns_records_on_success(self):
        with patch("src.subdomain_takeover.dns.resolver.Resolver") as MockResolver:
            instance = MockResolver.return_value

            cname_answer = MagicMock()
            cname_rr = MagicMock()
            cname_rr.target = dns.name.from_text("target.github.io.")
            cname_answer.__iter__ = lambda self: iter([cname_rr])
            cname_answer.__getitem__ = lambda self, idx: cname_rr

            a_answer = MagicMock()
            a_rr = MagicMock()
            a_rr.to_text.return_value = "1.2.3.4"
            a_answer.__iter__ = lambda self: iter([a_rr])

            def side_effect(fqdn, rdtype):
                if rdtype == "CNAME":
                    return cname_answer
                return a_answer

            instance.resolve.side_effect = side_effect
            result = await _resolve_subdomain("blog.example.com")
            assert result is not None
            assert result["fqdn"] == "blog.example.com"
            assert result["cname"] == "target.github.io"
            assert "1.2.3.4" in result["a_records"]


# ---------------------------------------------------------------------------
# _verify_http
# ---------------------------------------------------------------------------

class TestVerifyHttp:
    @pytest.mark.asyncio
    async def test_fingerprint_match(self):
        mock_resp = MagicMock()
        mock_resp.text = "There isn't a GitHub Pages site here."
        mock_resp.status_code = 404

        with patch("src.subdomain_takeover.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            matched, evidence = await _verify_http(
                "blog.example.com",
                ["There isn't a GitHub Pages site here."],
            )
            assert matched is True
            assert any("body contains" in e for e in evidence)

    @pytest.mark.asyncio
    async def test_no_fingerprint_match(self):
        mock_resp = MagicMock()
        mock_resp.text = "Welcome to our website!"
        mock_resp.status_code = 200

        with patch("src.subdomain_takeover.httpx.AsyncClient") as MockClient:
            mock_client = AsyncMock()
            mock_client.get.return_value = mock_resp
            MockClient.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            matched, evidence = await _verify_http(
                "blog.example.com",
                ["There isn't a GitHub Pages site here."],
            )
            assert matched is False


# ---------------------------------------------------------------------------
# enumerate_subdomains
# ---------------------------------------------------------------------------

class TestEnumerateSubdomains:
    @pytest.mark.asyncio
    async def test_combines_ct_and_permutation(self):
        with patch("src.subdomain_takeover._resolve_subdomain") as mock_resolve:
            mock_resolve.return_value = None
            result = await enumerate_subdomains(
                "example.com",
                known_subdomains=["api.example.com", "blog.example.com"],
            )
            assert result["domain"] == "example.com"
            assert result["sources"]["ct_candidates"] == 2
            assert result["sources"]["permutation_candidates"] > 100

    @pytest.mark.asyncio
    async def test_deduplicates_known_vs_wordlist(self):
        call_count = 0

        async def counting_resolve(fqdn, timeout=5):
            nonlocal call_count
            call_count += 1
            return None

        with patch("src.subdomain_takeover._resolve_subdomain", side_effect=counting_resolve):
            result = await enumerate_subdomains(
                "example.com",
                known_subdomains=["api.example.com"],
            )
            total_candidates = (
                result["sources"]["ct_candidates"]
                + result["sources"]["permutation_candidates"]
            )
            assert call_count == total_candidates

    @pytest.mark.asyncio
    async def test_filters_non_matching_subdomains(self):
        with patch("src.subdomain_takeover._resolve_subdomain", return_value=None):
            result = await enumerate_subdomains(
                "example.com",
                known_subdomains=["other.different.com", "example.com"],
            )
            assert result["sources"]["ct_candidates"] == 0


# ---------------------------------------------------------------------------
# check_takeovers
# ---------------------------------------------------------------------------

class TestCheckTakeovers:
    @pytest.mark.asyncio
    async def test_detects_vulnerable_subdomain(self):
        resolved = [
            {
                "fqdn": "blog.example.com",
                "a_records": [],
                "cname": "user.github.io",
            }
        ]
        with patch("src.subdomain_takeover._check_cname_dangling", return_value=True):
            with patch("src.subdomain_takeover._verify_http", return_value=(True, ["fingerprint match"])):
                findings = await check_takeovers(resolved)
                assert len(findings) == 1
                assert findings[0].status == "vulnerable"
                assert findings[0].vulnerable_service == "GitHub Pages"
                assert findings[0].severity == "critical"

    @pytest.mark.asyncio
    async def test_service_detected_not_vulnerable(self):
        resolved = [
            {
                "fqdn": "shop.example.com",
                "a_records": ["1.2.3.4"],
                "cname": "stores.myshopify.com",
            }
        ]
        with patch("src.subdomain_takeover._check_cname_dangling", return_value=False):
            with patch("src.subdomain_takeover._verify_http", return_value=(False, [])):
                findings = await check_takeovers(resolved)
                assert len(findings) == 1
                assert findings[0].status == "service_detected"
                assert findings[0].severity == "info"

    @pytest.mark.asyncio
    async def test_skips_no_cname(self):
        resolved = [
            {"fqdn": "www.example.com", "a_records": ["1.2.3.4"], "cname": ""},
        ]
        findings = await check_takeovers(resolved)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_skips_unrecognised_cname(self):
        resolved = [
            {"fqdn": "cdn.example.com", "a_records": ["1.2.3.4"], "cname": "cdn.someother.com"},
        ]
        findings = await check_takeovers(resolved)
        assert len(findings) == 0

    @pytest.mark.asyncio
    async def test_dangling_without_http_match(self):
        resolved = [
            {"fqdn": "old.example.com", "a_records": [], "cname": "old.herokuapp.com"},
        ]
        with patch("src.subdomain_takeover._check_cname_dangling", return_value=True):
            with patch("src.subdomain_takeover._verify_http", return_value=(False, [])):
                findings = await check_takeovers(resolved)
                assert len(findings) == 1
                assert findings[0].status == "vulnerable"

    @pytest.mark.asyncio
    async def test_http_match_without_dangling(self):
        resolved = [
            {"fqdn": "app.example.com", "a_records": ["1.2.3.4"], "cname": "app.netlify.app"},
        ]
        with patch("src.subdomain_takeover._check_cname_dangling", return_value=False):
            with patch("src.subdomain_takeover._verify_http", return_value=(True, ["fingerprint"])):
                findings = await check_takeovers(resolved)
                assert len(findings) == 1
                assert findings[0].status == "likely_vulnerable"
                assert findings[0].severity == "high"


# ---------------------------------------------------------------------------
# scan_subdomain_takeover (orchestrator)
# ---------------------------------------------------------------------------

class TestScanSubdomainTakeover:
    @pytest.mark.asyncio
    async def test_returns_result_on_success(self):
        with patch("src.subdomain_takeover.enumerate_subdomains") as mock_enum:
            mock_enum.return_value = {
                "domain": "example.com",
                "live_subdomains": ["api.example.com"],
                "resolved": [
                    {"fqdn": "api.example.com", "a_records": ["1.2.3.4"], "cname": ""},
                ],
                "sources": {"ct_candidates": 0, "permutation_candidates": 150, "ct_live": 0, "permutation_live": 1},
            }
            with patch("src.subdomain_takeover.check_takeovers", return_value=[]):
                result = await scan_subdomain_takeover("example.com")
                assert result.domain == "example.com"
                assert result.enumeration.domain == "example.com"
                assert len(result.enumeration.live_subdomains) == 1
                assert result.subdomains_checked == 1
                assert result.scan_duration_seconds >= 0
                assert result.error is None

    @pytest.mark.asyncio
    async def test_handles_enumeration_failure(self):
        with patch("src.subdomain_takeover.enumerate_subdomains", side_effect=Exception("DNS timeout")):
            result = await scan_subdomain_takeover("example.com")
            assert result.domain == "example.com"
            assert result.error == "DNS timeout"
            assert result.enumeration.error == "DNS timeout"

    @pytest.mark.asyncio
    async def test_handles_takeover_check_failure(self):
        with patch("src.subdomain_takeover.enumerate_subdomains") as mock_enum:
            mock_enum.return_value = {
                "domain": "example.com",
                "live_subdomains": ["api.example.com"],
                "resolved": [
                    {"fqdn": "api.example.com", "a_records": ["1.2.3.4"], "cname": "x.github.io"},
                ],
                "sources": {"ct_candidates": 0, "permutation_candidates": 150, "ct_live": 0, "permutation_live": 1},
            }
            with patch("src.subdomain_takeover.check_takeovers", side_effect=Exception("HTTP fail")):
                result = await scan_subdomain_takeover("example.com")
                assert result.domain == "example.com"
                assert result.findings == []
                assert result.error is None

    @pytest.mark.asyncio
    async def test_passes_known_subdomains(self):
        with patch("src.subdomain_takeover.enumerate_subdomains") as mock_enum:
            mock_enum.return_value = {
                "domain": "example.com",
                "live_subdomains": [],
                "resolved": [],
                "sources": {"ct_candidates": 2, "permutation_candidates": 150, "ct_live": 0, "permutation_live": 0},
            }
            with patch("src.subdomain_takeover.check_takeovers", return_value=[]):
                await scan_subdomain_takeover(
                    "example.com",
                    known_subdomains=["a.example.com", "b.example.com"],
                )
                mock_enum.assert_called_once()
                call_args = mock_enum.call_args
                assert call_args.kwargs.get("known_subdomains") == ["a.example.com", "b.example.com"] or \
                    (len(call_args.args) > 1 and call_args.args[1] == ["a.example.com", "b.example.com"])


# ---------------------------------------------------------------------------
# FAIR signal integration
# ---------------------------------------------------------------------------

class TestFAIRIntegration:
    def test_takeover_signal_emitted(self):
        from src.models import (
            DomainResult,
            DomainSummary,
            SubdomainEnumResult,
            SubdomainTakeoverFinding,
            SubdomainTakeoverResult,
            VulnerabilitiesGroup,
        )
        from src.fair_signals import compute_fair_signals

        finding = SubdomainTakeoverFinding(
            subdomain="old.example.com",
            cname_target="old.herokuapp.com",
            vulnerable_service="Heroku",
            status="vulnerable",
            severity="critical",
            evidence=["CNAME dangling"],
            remediation="Remove CNAME",
        )
        takeover = SubdomainTakeoverResult(
            domain="example.com",
            enumeration=SubdomainEnumResult(domain="example.com"),
            findings=[finding],
            subdomains_checked=5,
        )

        result = DomainResult(
            target="https://example.com",
            summary=DomainSummary(),
            vulnerabilities=VulnerabilitiesGroup(subdomain_takeover=takeover),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        vuln_signals = signals.vulnerability.signals
        names = [s.name for s in vuln_signals]
        assert "subdomain_takeover_risk" in names
        takeover_sig = next(s for s in vuln_signals if s.name == "subdomain_takeover_risk")
        assert takeover_sig.score == 100
        assert takeover_sig.weight == 1.5

    def test_no_signal_when_no_findings(self):
        from src.models import (
            DomainResult,
            DomainSummary,
            SubdomainEnumResult,
            SubdomainTakeoverResult,
            VulnerabilitiesGroup,
        )
        from src.fair_signals import compute_fair_signals

        takeover = SubdomainTakeoverResult(
            domain="example.com",
            enumeration=SubdomainEnumResult(domain="example.com"),
            findings=[],
            subdomains_checked=5,
        )
        result = DomainResult(
            target="https://example.com",
            summary=DomainSummary(),
            vulnerabilities=VulnerabilitiesGroup(subdomain_takeover=takeover),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        names = [s.name for s in signals.vulnerability.signals]
        assert "subdomain_takeover_risk" not in names

    def test_high_severity_score(self):
        from src.models import (
            DomainResult,
            DomainSummary,
            SubdomainEnumResult,
            SubdomainTakeoverFinding,
            SubdomainTakeoverResult,
            VulnerabilitiesGroup,
        )
        from src.fair_signals import compute_fair_signals

        finding = SubdomainTakeoverFinding(
            subdomain="shop.example.com",
            cname_target="stores.myshopify.com",
            vulnerable_service="Shopify",
            status="likely_vulnerable",
            severity="high",
            evidence=["fingerprint match"],
        )
        takeover = SubdomainTakeoverResult(
            domain="example.com",
            enumeration=SubdomainEnumResult(domain="example.com"),
            findings=[finding],
        )
        result = DomainResult(
            target="https://example.com",
            summary=DomainSummary(),
            vulnerabilities=VulnerabilitiesGroup(subdomain_takeover=takeover),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        takeover_sig = next(
            s for s in signals.vulnerability.signals
            if s.name == "subdomain_takeover_risk"
        )
        assert takeover_sig.score == 75
