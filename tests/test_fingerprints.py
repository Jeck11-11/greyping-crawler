"""Tests for finding fingerprint stability and EPSS/KEV enrichment."""

from unittest.mock import AsyncMock, patch

import pytest

from src.models import (
    BreachRecord,
    CloudAssetFinding,
    CookieFinding,
    CVEFinding,
    HeaderFinding,
    IoCFinding,
    NucleiFinding,
    OpenPort,
    PrioritizedFinding,
    PrivacyIndicator,
    SensitivePathFinding,
    SecretFinding,
    SubdomainTakeoverFinding,
    TyposquatCandidate,
    FindingClassification,
    FindingOwner,
    ScanResponse,
    _fingerprint,
)


class TestFingerprintHelper:
    def test_deterministic(self):
        assert _fingerprint("a", "b", "c") == _fingerprint("a", "b", "c")

    def test_different_inputs_different_hash(self):
        assert _fingerprint("a", "b") != _fingerprint("a", "c")

    def test_length_is_16(self):
        assert len(_fingerprint("test")) == 16

    def test_hex_chars_only(self):
        fp = _fingerprint("anything", "here")
        assert all(c in "0123456789abcdef" for c in fp)


class TestSecretFindingFingerprint:
    def test_auto_generated(self):
        s = SecretFinding(secret_type="aws_access_key", matched_pattern="test", value_preview="AKIA****1234", location="script")
        assert s.fingerprint
        assert len(s.fingerprint) == 16

    def test_stable_across_instances(self):
        kwargs = dict(secret_type="aws_access_key", matched_pattern="test", value_preview="AKIA****1234", location="script", found_on="https://example.com")
        s1 = SecretFinding(**kwargs)
        s2 = SecretFinding(**kwargs)
        assert s1.fingerprint == s2.fingerprint

    def test_different_type_different_fingerprint(self):
        base = dict(matched_pattern="test", value_preview="xxxx", location="script")
        s1 = SecretFinding(secret_type="aws_access_key", **base)
        s2 = SecretFinding(secret_type="github_token", **base)
        assert s1.fingerprint != s2.fingerprint

    def test_explicit_fingerprint_not_overwritten(self):
        s = SecretFinding(secret_type="aws", matched_pattern="t", value_preview="x", location="s", fingerprint="custom123")
        assert s.fingerprint == "custom123"


class TestHeaderFindingFingerprint:
    def test_auto_generated(self):
        h = HeaderFinding(header="Strict-Transport-Security", status="missing")
        assert h.fingerprint
        assert len(h.fingerprint) == 16

    def test_same_header_same_status(self):
        h1 = HeaderFinding(header="X-Frame-Options", status="missing")
        h2 = HeaderFinding(header="X-Frame-Options", status="missing")
        assert h1.fingerprint == h2.fingerprint

    def test_different_status_different_fingerprint(self):
        h1 = HeaderFinding(header="HSTS", status="missing")
        h2 = HeaderFinding(header="HSTS", status="weak")
        assert h1.fingerprint != h2.fingerprint


class TestCookieFindingFingerprint:
    def test_auto_generated(self):
        c = CookieFinding(name="session_id", issues=["missing Secure", "missing HttpOnly"])
        assert c.fingerprint

    def test_issue_order_irrelevant(self):
        c1 = CookieFinding(name="sid", issues=["missing Secure", "missing HttpOnly"])
        c2 = CookieFinding(name="sid", issues=["missing HttpOnly", "missing Secure"])
        assert c1.fingerprint == c2.fingerprint


class TestSensitivePathFindingFingerprint:
    def test_auto_generated(self):
        p = SensitivePathFinding(path="/.env", status_code=200)
        assert p.fingerprint

    def test_different_status_code(self):
        p1 = SensitivePathFinding(path="/.env", status_code=200)
        p2 = SensitivePathFinding(path="/.env", status_code=403)
        assert p1.fingerprint != p2.fingerprint


class TestIoCFindingFingerprint:
    def test_auto_generated(self):
        i = IoCFinding(ioc_type="cryptominer", description="test", evidence="coinhive.min.js")
        assert i.fingerprint

    def test_stable(self):
        kwargs = dict(ioc_type="cryptominer", description="test", evidence="coinhive.min.js")
        assert IoCFinding(**kwargs).fingerprint == IoCFinding(**kwargs).fingerprint


class TestCVEFindingFingerprint:
    def test_auto_generated(self):
        c = CVEFinding(cve_id="CVE-2024-1234", affected_tech="jQuery")
        assert c.fingerprint

    def test_epss_fields_default(self):
        c = CVEFinding(cve_id="CVE-2024-1234")
        assert c.epss_score is None
        assert c.epss_percentile is None
        assert c.in_kev is False
        assert c.kev_due_date == ""

    def test_epss_fields_set(self):
        c = CVEFinding(cve_id="CVE-2024-1234", epss_score=0.95, epss_percentile=0.99, in_kev=True, kev_due_date="2024-06-01")
        assert c.epss_score == 0.95
        assert c.in_kev is True


class TestNucleiFindingFingerprint:
    def test_auto_generated(self):
        n = NucleiFinding(template_id="cve-2021-44228", matched_at="https://example.com")
        assert n.fingerprint

    def test_stable(self):
        kwargs = dict(template_id="xss-reflected", matched_at="https://example.com/search")
        assert NucleiFinding(**kwargs).fingerprint == NucleiFinding(**kwargs).fingerprint


class TestSubdomainTakeoverFindingFingerprint:
    def test_auto_generated(self):
        f = SubdomainTakeoverFinding(subdomain="old.example.com", cname_target="old.github.io", vulnerable_service="GitHub Pages", status="vulnerable", severity="critical")
        assert f.fingerprint

    def test_stable(self):
        kwargs = dict(subdomain="x.example.com", cname_target="x.github.io", vulnerable_service="GitHub Pages", status="vulnerable", severity="critical")
        assert SubdomainTakeoverFinding(**kwargs).fingerprint == SubdomainTakeoverFinding(**kwargs).fingerprint


class TestBreachRecordFingerprint:
    def test_auto_generated(self):
        b = BreachRecord(source="haveibeenpwned", breach_name="LinkedIn", domain="linkedin.com")
        assert b.fingerprint

    def test_stable(self):
        kwargs = dict(source="hibp", breach_name="Adobe", domain="adobe.com")
        assert BreachRecord(**kwargs).fingerprint == BreachRecord(**kwargs).fingerprint


class TestTyposquatCandidateFingerprint:
    def test_auto_generated(self):
        t = TyposquatCandidate(domain="examp1e.com")
        assert t.fingerprint

    def test_different_domains(self):
        t1 = TyposquatCandidate(domain="examp1e.com")
        t2 = TyposquatCandidate(domain="exampl3.com")
        assert t1.fingerprint != t2.fingerprint


class TestPrivacyIndicatorFingerprint:
    def test_auto_generated(self):
        p = PrivacyIndicator(name="privacy_policy", present=True)
        assert p.fingerprint

    def test_different_state(self):
        p1 = PrivacyIndicator(name="cookie_consent", present=True)
        p2 = PrivacyIndicator(name="cookie_consent", present=False)
        assert p1.fingerprint != p2.fingerprint


class TestCloudAssetFindingFingerprint:
    def test_auto_generated(self):
        c = CloudAssetFinding(bucket_name="example-backup", provider="aws_s3", status="public")
        assert c.fingerprint

    def test_stable(self):
        kwargs = dict(bucket_name="example-backup", provider="aws_s3", status="public")
        assert CloudAssetFinding(**kwargs).fingerprint == CloudAssetFinding(**kwargs).fingerprint


class TestOpenPortFingerprint:
    def test_auto_generated(self):
        o = OpenPort(port=443, service="https")
        assert o.fingerprint

    def test_different_port(self):
        o1 = OpenPort(port=80, service="http")
        o2 = OpenPort(port=443, service="https")
        assert o1.fingerprint != o2.fingerprint


class TestPrioritizedFindingFingerprint:
    def test_auto_generated(self):
        p = PrioritizedFinding(id="missing_hsts", title="Missing HSTS", category="security_headers", classification=FindingClassification.confirmed_issue, owner=FindingOwner.customer)
        assert p.fingerprint

    def test_stable(self):
        kwargs = dict(id="ssl_invalid", title="SSL Invalid", category="ssl", classification=FindingClassification.confirmed_issue, owner=FindingOwner.customer)
        assert PrioritizedFinding(**kwargs).fingerprint == PrioritizedFinding(**kwargs).fingerprint


class TestScannerVersion:
    def test_scanner_version_present(self):
        r = ScanResponse(scan_id="test123")
        assert r.scanner_version == "1.4.0"


# ---------------------------------------------------------------------------
# EPSS / KEV enrichment tests
# ---------------------------------------------------------------------------

class TestEpssKevEnrichment:
    @pytest.mark.asyncio
    async def test_enrich_cves_with_epss_and_kev(self):
        from src.cve_lookup import enrich_cves_with_epss_kev

        findings = [
            CVEFinding(cve_id="CVE-2024-1234", severity="HIGH", affected_tech="jQuery"),
            CVEFinding(cve_id="CVE-2024-5678", severity="MEDIUM", affected_tech="jQuery"),
        ]

        epss_data = {
            "CVE-2024-1234": {"score": 0.95432, "percentile": 0.99123},
            "CVE-2024-5678": {"score": 0.01234, "percentile": 0.45678},
        }
        kev_map = {"CVE-2024-1234": "2024-06-15"}

        with patch("src.cve_lookup._fetch_epss_batch", new_callable=AsyncMock, return_value=epss_data), \
             patch("src.cve_lookup._load_kev_catalog", new_callable=AsyncMock, return_value=kev_map):
            await enrich_cves_with_epss_kev(findings)

        assert findings[0].epss_score == pytest.approx(0.95432)
        assert findings[0].epss_percentile == pytest.approx(0.99123)
        assert findings[0].in_kev is True
        assert findings[0].kev_due_date == "2024-06-15"

        assert findings[1].epss_score == pytest.approx(0.01234)
        assert findings[1].in_kev is False
        assert findings[1].kev_due_date == ""

    @pytest.mark.asyncio
    async def test_enrich_empty_list(self):
        from src.cve_lookup import enrich_cves_with_epss_kev
        await enrich_cves_with_epss_kev([])

    @pytest.mark.asyncio
    async def test_enrich_non_cve_ids_skipped(self):
        from src.cve_lookup import enrich_cves_with_epss_kev
        findings = [CVEFinding(cve_id="GHSA-xxxx-yyyy", severity="HIGH")]
        await enrich_cves_with_epss_kev(findings)
        assert findings[0].epss_score is None

    @pytest.mark.asyncio
    async def test_enrich_handles_epss_failure(self):
        from src.cve_lookup import enrich_cves_with_epss_kev

        findings = [CVEFinding(cve_id="CVE-2024-9999", severity="HIGH")]

        with patch("src.cve_lookup._fetch_epss_batch", new_callable=AsyncMock, side_effect=Exception("timeout")), \
             patch("src.cve_lookup._load_kev_catalog", new_callable=AsyncMock, return_value={}):
            await enrich_cves_with_epss_kev(findings)

        assert findings[0].epss_score is None
        assert findings[0].in_kev is False

    @pytest.mark.asyncio
    async def test_enrich_handles_kev_failure(self):
        from src.cve_lookup import enrich_cves_with_epss_kev

        findings = [CVEFinding(cve_id="CVE-2024-9999", severity="HIGH")]

        with patch("src.cve_lookup._fetch_epss_batch", new_callable=AsyncMock, return_value={}), \
             patch("src.cve_lookup._load_kev_catalog", new_callable=AsyncMock, side_effect=Exception("timeout")):
            await enrich_cves_with_epss_kev(findings)

        assert findings[0].epss_score is None
        assert findings[0].in_kev is False
