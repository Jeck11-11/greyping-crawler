"""Phase B correctness fixes — acceptance tests.

Covers spec Tests 3 (Cloudflare ports), 6 (bucket AccessDenied), 9 (typosquat
candidate), 10 (privacy indicators).
"""

from __future__ import annotations

from src.port_scanner import classify_network_attribution
from src.models import (
    CloudAssetResult,
    DomainResult,
    OpenPort,
    PortScanResult,
    PrivacyComplianceResult,
    PrivacyIndicator,
    RiskAssessmentGroup,
    TyposquatCandidate,
    TyposquattingResult,
    FindingClassification,
)
from src.easm_report import (
    _classify_port_findings,
    _classify_typosquatting_findings,
    _classify_privacy_findings,
)


# --------------------------------------------------------------------------
# Test 3 — Cloudflare ports are shared-edge, not customer origin
# --------------------------------------------------------------------------

class TestCloudflarePorts:
    def test_cloudflare_ip_is_shared_edge(self):
        attribution, provider = classify_network_attribution("104.16.1.1")
        assert attribution == "shared_cdn_edge"
        assert provider == "Cloudflare"

    def test_origin_ip_is_origin(self):
        attribution, provider = classify_network_attribution("203.0.113.10")
        assert attribution == "origin"

    def test_cpanel_ports_on_cdn_not_confirmed_finding(self):
        ps = PortScanResult(
            target="dnait.ie",
            ip="104.16.1.1",
            network_attribution="shared_cdn_edge",
            cdn_provider="Cloudflare",
            open_ports=[
                OpenPort(port=2082, service="cPanel", banner="",
                         network_attribution="shared_cdn_edge",
                         affects_risk_score=False, service_confirmed=False),
                OpenPort(port=8443, service="HTTPS-alt", banner="",
                         network_attribution="shared_cdn_edge",
                         affects_risk_score=False, service_confirmed=False),
            ],
        )
        result = DomainResult(target="dnait.ie", port_scan=ps)
        findings = _classify_port_findings(result)
        # No confirmed cPanel/data-breach finding; only informational observations.
        assert all(f.classification == FindingClassification.attack_surface_observation for f in findings)
        assert all(f.affects_risk_score is False for f in findings)
        assert all("firewall" not in f.recommended_action.lower() or "do not" in f.recommended_action.lower()
                   for f in findings)
        assert not any("data breach" in f.business_impact.lower() for f in findings)


# --------------------------------------------------------------------------
# Test 6 — Bucket AccessDenied is an unverified candidate, not owned
# --------------------------------------------------------------------------

class TestBucketAccessDenied:
    def test_counts_default_to_zero_confirmed(self):
        r = CloudAssetResult(domain="dnait.ie")
        assert r.confirmed_owned_buckets == 0
        assert r.publicly_exposed_buckets == 0

    def test_access_denied_does_not_score(self):
        # Simulate the finding an AccessDenied response would produce.
        from src.models import CloudAssetFinding
        f = CloudAssetFinding(
            bucket_name="dnait-backup", provider="s3", status="exists_private",
            classification="unverified_asset_candidate",
        )
        assert f.ownership_verified is False
        assert f.public_exposure_confirmed is False
        assert f.affects_risk_score is False
        assert f.severity == "informational"


# --------------------------------------------------------------------------
# Test 9 — Typosquat candidate is informational, not confirmed
# --------------------------------------------------------------------------

class TestTyposquatCandidate:
    def test_registered_lookalike_is_risk_candidate(self):
        result = DomainResult(
            target="dnait.ie",
            typosquatting=TyposquattingResult(
                domain="dnait.ie",
                registered_candidates=[
                    TyposquatCandidate(domain="dnait.com", a_records=["1.2.3.4"],
                                       technique="tld_swap", similarity_score=0.95),
                ],
            ),
        )
        findings = _classify_typosquatting_findings(result)
        assert len(findings) == 1
        f = findings[0]
        assert f.classification == FindingClassification.risk_candidate
        assert f.severity == "informational"
        assert f.affects_risk_score is False
        assert "not been confirmed" in f.why_it_matters.lower()
        assert "takedown" not in f.recommended_action.lower() or "confirmed" in f.recommended_action.lower()


# --------------------------------------------------------------------------
# Test 10 — Privacy indicators, no confirmed GDPR violation
# --------------------------------------------------------------------------

class TestPrivacyIndicators:
    def test_privacy_result_fields(self):
        r = PrivacyComplianceResult(domain="dnait.ie", consent_tool="")
        assert r.consent_platform == "not_detected"
        assert r.nonessential_tracking_before_consent == "not_assessed"
        assert r.manual_validation_required is True

    def test_missing_consent_not_confirmed_violation(self):
        result = DomainResult(
            target="dnait.ie",
            privacy=PrivacyComplianceResult(
                domain="dnait.ie",
                score=50,
                indicators=[
                    PrivacyIndicator(name="privacy_policy", present=True),
                    PrivacyIndicator(name="cookie_consent_tool", present=False),
                ],
            ),
        )
        findings = _classify_privacy_findings(result)
        # No confirmed_issue about consent; the consent finding is a potential_issue.
        assert not any(f.classification == FindingClassification.confirmed_issue for f in findings)
        consent = [f for f in findings if f.id == "consent_platform_not_detected"]
        assert consent and consent[0].classification == FindingClassification.potential_issue
        assert consent[0].affects_risk_score is False
