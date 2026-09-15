"""Regression locks for the frontend-facing v1 scanner JSON shape."""

from src.models import (
    AsyncScanAck,
    AsyncScanJobStatus,
    BoardJobStatus,
    BoardScanAck,
    DomainResult,
    EASMReport,
    ScanResponse,
)


def test_scan_response_and_domain_result_v1_keys_are_locked():
    payload = ScanResponse(
        scan_id="contract",
        results=[DomainResult(target="https://example.com")],
    ).model_dump(mode="json")

    assert set(payload) == {
        "scan_id", "status", "started_at", "finished_at", "summary",
        "total_targets", "results", "scanner_version",
    }
    assert set(payload["results"][0]) == {
        "target", "scan_started_at", "scan_finished_at", "error", "metadata",
        "summary", "ssl", "dns", "security", "contacts", "links", "pages",
        "technologies", "breaches", "js_intel", "supply_chain", "port_scan",
        "cloud_assets", "passive_intel", "vulnerabilities", "reputation", "waf",
        "typosquatting", "privacy", "email_validations", "screenshots", "favicon",
        "robots_txt", "sitemap", "attack_paths", "risk_assessment",
    }
    assert set(payload["results"][0]["security"]) == {
        "headers", "cookies", "sensitive_paths", "secrets", "ioc_findings",
    }


def test_v1_job_and_report_model_keys_are_locked():
    assert set(EASMReport.model_fields) == {
        "generated_at", "scan_mode", "overall_grade", "executive_summary",
        "ransomware_susceptibility", "financial_impact", "compliance_posture",
        "asset_context", "asset_classification", "cloud_assets", "recon_artifacts",
        "prioritized_findings", "total_findings", "confirmed_issues",
        "platform_behaviors", "informational_count", "severity_breakdown",
        "posture_summary", "remediation_priorities", "risk_tier", "scan_confidence",
        "score_inputs", "excluded_inputs", "compliance_summary", "platform_detected",
    }
    assert set(BoardScanAck.model_fields) == {
        "scan_id", "status", "root_domain", "started_at", "poll_url", "message",
    }
    assert set(BoardJobStatus.model_fields) == {
        "scan_id", "status", "root_domain", "started_at", "finished_at",
        "subdomains_discovered", "targets_total", "targets_completed", "board_report",
        "results", "error", "scanner_version",
    }
    assert set(AsyncScanAck.model_fields) == {
        "scan_id", "status", "targets_total", "poll_url", "message",
    }
    assert set(AsyncScanJobStatus.model_fields) == {
        "scan_id", "status", "started_at", "finished_at", "targets_total",
        "targets_completed", "targets_failed", "delivered", "rows", "error",
    }


def test_v1_core_field_types_remain_stable():
    payload = ScanResponse(
        scan_id="contract",
        results=[DomainResult(target="https://example.com")],
    ).model_dump(mode="json")
    result = payload["results"][0]

    assert isinstance(payload["scan_id"], str)
    assert isinstance(payload["status"], str)
    assert isinstance(payload["summary"], dict)
    assert isinstance(payload["total_targets"], int)
    assert isinstance(payload["results"], list)
    assert isinstance(result["metadata"], dict)
    assert isinstance(result["security"], dict)
    assert isinstance(result["technologies"], list)
    assert result["error"] is None or isinstance(result["error"], str)
