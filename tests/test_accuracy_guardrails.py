"""Accuracy guardrails for unknown evidence and heuristic promotion."""

from src.app import _analyze_observed_headers, _extract_domain
from src.easm_report import (
    _classify_cloud_findings,
    _classify_ioc_findings,
    _classify_supply_chain_findings,
    build_easm_report,
)
from src.models import (
    CloudAssetFinding,
    CloudAssetResult,
    CloudServiceFinding,
    DomainResult,
    FindingClassification,
    IoCFinding,
    SecurityGroup,
    SupplyChainResult,
    ThirdPartyResource,
)
from src.security_headers import analyze_headers


def test_transport_failure_does_not_create_missing_header_findings():
    headers = _analyze_observed_headers({}, "")
    assert headers.grade == ""
    assert headers.findings == []


def test_www_normalization_does_not_strip_real_hostname_characters():
    assert _extract_domain("https://www.example.com") == "example.com"
    assert _extract_domain("https://wow.com") == "wow.com"


def test_empty_evidence_has_no_grade_or_compliance_passes():
    report = build_easm_report(DomainResult(target="https://example.com"), scan_mode="passive")
    assert report.overall_grade == ""
    assert report.risk_tier == ""
    assert report.executive_summary.risk_posture == "Unknown"
    assert report.executive_summary.key_positives == []
    assert report.scan_confidence == "low"
    assert all(posture.controls_passing == 0 for posture in report.compliance_posture)
    assert all(posture.readiness_score == 0 for posture in report.compliance_posture)


def test_html_ioc_heuristic_is_potential_and_non_scoring():
    result = DomainResult(
        target="https://example.com",
        security=SecurityGroup(ioc_findings=[
            IoCFinding(
                ioc_type="hidden_iframe",
                description="Hidden external iframe",
                evidence="https://unknown.example/frame",
                severity="high",
            ),
        ]),
    )
    finding = _classify_ioc_findings(result)[0]
    assert finding.classification == FindingClassification.potential_issue
    assert finding.affects_risk_score is False


def test_known_cryptominer_remains_confirmed():
    result = DomainResult(
        target="https://example.com",
        security=SecurityGroup(ioc_findings=[
            IoCFinding(
                ioc_type="cryptominer",
                description="Known miner",
                evidence="coinhive.com/lib.js",
                severity="critical",
            ),
        ]),
    )
    finding = _classify_ioc_findings(result)[0]
    assert finding.classification == FindingClassification.confirmed_issue
    assert finding.affects_risk_score is True


def test_cors_header_alone_requires_active_validation_before_scoring():
    result = DomainResult(
        target="https://example.com",
        security=SecurityGroup(headers=analyze_headers({
            "Access-Control-Allow-Origin": "*",
        })),
    )
    report = build_easm_report(result)
    finding = next(f for f in report.prioritized_findings if f.id == "cors_wildcard")
    assert finding.classification == FindingClassification.potential_issue
    assert finding.affects_risk_score is False
    assert finding.compliance == []


def test_public_bucket_requires_verified_ownership_to_score():
    result = DomainResult(
        target="https://example.com",
        cloud_assets=CloudAssetResult(
            domain="example.com",
            findings=[CloudAssetFinding(
                bucket_name="example-backup",
                provider="aws_s3",
                status="public",
                public_exposure_confirmed=True,
                ownership_verified=False,
            )],
        ),
    )
    finding = _classify_cloud_findings(result)[0]
    assert finding.classification == FindingClassification.risk_candidate
    assert finding.affects_risk_score is False


def test_dns_database_name_is_observation_not_confirmed_exposure():
    result = DomainResult(
        target="https://example.com",
        cloud_assets=CloudAssetResult(
            domain="example.com",
            cloud_services=[CloudServiceFinding(
                service="aws_rds",
                provider="aws",
                record_value="db.example.rds.amazonaws.com",
                is_database=True,
            )],
        ),
    )
    finding = _classify_cloud_findings(result)[0]
    assert finding.classification == FindingClassification.attack_surface_observation
    assert finding.affects_risk_score is False


def test_missing_sri_is_hardening_candidate_not_confirmed_compromise():
    result = DomainResult(
        target="https://example.com",
        supply_chain=SupplyChainResult(
            scripts_without_sri=1,
            resources=[ThirdPartyResource(
                url="https://cdn.example.net/app.js",
                resource_type="script",
                has_sri=False,
            )],
        ),
    )
    finding = _classify_supply_chain_findings(result)[0]
    assert finding.classification == FindingClassification.potential_issue
    assert finding.affects_risk_score is False
