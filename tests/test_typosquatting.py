"""Tests for the typosquatting detection module."""

from unittest.mock import AsyncMock, patch

import pytest

from src.typosquatting import generate_typo_candidates, check_typosquatting, _similarity


class TestGenerateTypoCandidates:
    def test_generates_omission_candidates(self):
        candidates = generate_typo_candidates("example.com")
        domains = [c["domain"] for c in candidates]
        assert "xample.com" in domains
        assert "examle.com" in domains

    def test_generates_transposition_candidates(self):
        candidates = generate_typo_candidates("example.com")
        domains = [c["domain"] for c in candidates]
        assert "exapmle.com" in domains

    def test_generates_duplication_candidates(self):
        candidates = generate_typo_candidates("example.com")
        domains = [c["domain"] for c in candidates]
        assert "eexample.com" in domains

    def test_generates_homoglyph_candidates(self):
        candidates = generate_typo_candidates("example.com")
        domains = [c["domain"] for c in candidates]
        assert "examp1e.com" in domains  # l -> 1
        assert "exampie.com" in domains  # l -> i

    def test_generates_tld_swap_candidates(self):
        candidates = generate_typo_candidates("example.com")
        domains = [c["domain"] for c in candidates]
        assert "example.net" in domains
        assert "example.org" in domains

    def test_no_duplicates(self):
        candidates = generate_typo_candidates("example.com")
        domains = [c["domain"] for c in candidates]
        assert len(domains) == len(set(domains))

    def test_original_domain_excluded(self):
        candidates = generate_typo_candidates("test.com")
        domains = [c["domain"] for c in candidates]
        assert "test.com" not in domains

    def test_empty_domain_returns_empty(self):
        assert generate_typo_candidates("") == []

    def test_no_tld_returns_empty(self):
        assert generate_typo_candidates("localhost") == []

    def test_techniques_are_labelled(self):
        candidates = generate_typo_candidates("abc.com")
        techniques = {c["technique"] for c in candidates}
        assert "omission" in techniques
        assert "tld_swap" in techniques


class TestSimilarity:
    def test_identical(self):
        assert _similarity("test", "test") == 1.0

    def test_one_char_diff(self):
        score = _similarity("test", "tast")
        assert 0.5 < score < 1.0

    def test_empty(self):
        assert _similarity("", "test") == 0.0


class TestCheckTyposquatting:
    @pytest.mark.asyncio
    @patch("src.typosquatting.dns.resolver.Resolver")
    async def test_returns_registered_candidates(self, mock_resolver_cls):
        mock_resolver = mock_resolver_cls.return_value
        mock_answer = type("Answer", (), {"__str__": lambda self: "1.2.3.4", "__iter__": lambda self: iter([self])})()
        mock_resolver.resolve.return_value = [mock_answer]

        result = await check_typosquatting("test.com", timeout=5, concurrency=5)

        assert result.domain == "test.com"
        assert result.candidates_checked > 0
        assert len(result.registered_candidates) > 0
        assert result.scan_duration_seconds >= 0

    @pytest.mark.asyncio
    @patch("src.typosquatting.dns.resolver.Resolver")
    async def test_handles_nxdomain(self, mock_resolver_cls):
        import dns.resolver
        mock_resolver = mock_resolver_cls.return_value
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        result = await check_typosquatting("test.com", timeout=5, concurrency=5)

        assert result.domain == "test.com"
        assert result.candidates_checked > 0
        assert len(result.registered_candidates) == 0

    @pytest.mark.asyncio
    @patch("src.typosquatting.dns.resolver.Resolver")
    async def test_candidates_sorted_by_similarity(self, mock_resolver_cls):
        call_count = 0

        def _resolve(domain, rtype):
            nonlocal call_count
            call_count += 1
            if call_count % 3 == 0:
                mock_answer = type("A", (), {"__str__": lambda self: "1.2.3.4", "__iter__": lambda self: iter([self])})()
                return [mock_answer]
            import dns.resolver
            raise dns.resolver.NXDOMAIN()

        mock_resolver = mock_resolver_cls.return_value
        mock_resolver.resolve.side_effect = _resolve

        result = await check_typosquatting("example.com", timeout=5, concurrency=5)

        if len(result.registered_candidates) >= 2:
            scores = [c.similarity_score for c in result.registered_candidates]
            assert scores == sorted(scores, reverse=True)
