"""Tests for the FAIR signal builder and its integration with the scanners."""

from unittest.mock import AsyncMock, patch

from src.models import ARecord

import httpx
from fastapi.testclient import TestClient

from src.app import app
from src.fair_signals import compute_fair_signals
from src.models import (
    BreachRecord,
    CookieFinding,
    CTResult,
    DNSResult,
    DomainResult,
    HeaderFinding,
    IoCFinding,
    JSIntelResult,
    PassiveIntelResult,
    RDAPResult,
    SecretFinding,
    SecurityHeadersResult,
    SensitivePathFinding,
    SSLCertResult,
    TechFinding,
    WaybackResult,
)


client = TestClient(app)


# ---------------------------------------------------------------------------
# Unit tests — compute_fair_signals
# ---------------------------------------------------------------------------

class TestFAIRBuilder:
    def test_empty_result_gets_neutral_score_and_low_confidence(self):
        result = DomainResult(target="https://empty.example.com")
        signals = compute_fair_signals(result, scan_mode="passive")

        # No evidence in any factor → each factor.score == 0, signals == [].
        assert signals.threat_event_frequency.signals == []
        assert signals.vulnerability.signals == []
        assert signals.control_strength.signals == []
        assert signals.loss_magnitude.signals == []
        # But derived values use neutral 50 so overall_risk isn't absurdly zero.
        assert signals.loss_event_frequency > 0
        assert signals.overall_risk > 0
        assert signals.confidence == "low"
        assert signals.scan_mode == "passive"

    def test_severe_vulnerabilities_push_overall_risk_to_critical(self):
        result = DomainResult(
            target="https://rotten.example.com",
            # TEF evidence: public surface + high-target CMS + API endpoints.
            technologies=[
                TechFinding(name="WordPress", categories=["cms"], version="5.0"),
            ],
            js_intel=JSIntelResult(
                target="https://rotten.example.com",
                scripts_scanned=4,
                api_endpoints=[
                    "/api/v1/users", "/api/v1/admin", "/api/v1/orders",
                    "/api/v1/payments", "/api/v1/secrets",
                ],
            ),
            passive_intel=PassiveIntelResult(
                ct=CTResult(
                    domain="rotten.example.com",
                    subdomains=[
                        f"sub{i}.rotten.example.com" for i in range(10)
                    ],
                ),
                wayback=WaybackResult(
                    domain="rotten.example.com", snapshot_count=200,
                ),
            ),
            secrets=[
                SecretFinding(
                    secret_type="aws_access_key",
                    matched_pattern="AKIA",
                    value_preview="AKIA...MPLE",
                    location="script",
                    severity="critical",
                ),
                SecretFinding(
                    secret_type="private_key",
                    matched_pattern="RSA",
                    value_preview="-----...KEY-----",
                    location="html_comment",
                    severity="critical",
                ),
            ],
            sensitive_paths=[
                SensitivePathFinding(
                    path="/.env", url="https://rotten.example.com/.env",
                    status_code=200, content_length=1024,
                    risk="Environment file exposed", severity="critical",
                ),
            ],
            ssl_certificate=SSLCertResult(
                is_valid=False, grade="F", issues=["self-signed", "expired"],
            ),
            security_headers=SecurityHeadersResult(
                grade="F", score=10,
                findings=[
                    HeaderFinding(
                        header="Strict-Transport-Security", status="missing",
                        severity="high",
                    ),
                    HeaderFinding(
                        header="Content-Security-Policy", status="missing",
                        severity="high",
                    ),
                ],
            ),
            breaches=[
                BreachRecord(
                    source="domain:rotten.example.com",
                    breach_name="MegaLeak 2023",
                    data_types=["Email addresses", "Passwords", "SSNs"],
                ),
            ],
        )

        signals = compute_fair_signals(result, scan_mode="full")
        assert signals.risk_tier in ("high", "critical")
        assert signals.overall_risk >= 50
        # All relevant factors populated.
        assert any(s.name == "exposed_secrets"
                   for s in signals.vulnerability.signals)
        assert any(s.name == "sensitive_paths_exposed"
                   for s in signals.vulnerability.signals)
        assert any(s.name == "credential_exposure"
                   for s in signals.loss_magnitude.signals)
        assert any(s.name == "breach_history"
                   for s in signals.loss_magnitude.signals)
        assert signals.confidence == "high"
        assert signals.scan_mode == "full"

    def test_strong_controls_attenuate_risk(self):
        clean = DomainResult(
            target="https://clean.example.com",
            ssl_certificate=SSLCertResult(is_valid=True, grade="A"),
            security_headers=SecurityHeadersResult(grade="A", score=95),
            cookies=[
                CookieFinding(
                    name="session", secure=True, http_only=True,
                    same_site="Strict",
                ),
            ],
            technologies=[
                TechFinding(name="Cloudflare", categories=["cdn"]),
            ],
        )
        signals = compute_fair_signals(clean, scan_mode="full")

        assert signals.control_strength.score >= 80
        assert any(s.name == "waf_or_cdn_detected"
                   for s in signals.control_strength.signals)
        # Strong controls should attenuate LEF vs the identical target with
        # no controls.
        bare = DomainResult(target="https://bare.example.com")
        bare_signals = compute_fair_signals(bare, scan_mode="full")
        assert signals.loss_event_frequency < bare_signals.loss_event_frequency

    def test_passive_only_populates_passive_derived_factors(self):
        result = DomainResult(
            target="https://lurker.example.com",
            passive_intel=PassiveIntelResult(
                dns=DNSResult(domain="lurker.example.com",
                              a_records=[ARecord(address="93.184.216.34")]),
                ct=CTResult(
                    domain="lurker.example.com",
                    subdomains=[
                        "api.lurker.example.com",
                        "admin.lurker.example.com",
                        "dev.lurker.example.com",
                    ],
                    certificates_seen=8,
                ),
                wayback=WaybackResult(
                    domain="lurker.example.com", snapshot_count=120,
                ),
                rdap=RDAPResult(domain="lurker.example.com"),
                breaches=[],
            ),
        )
        signals = compute_fair_signals(result, scan_mode="passive")

        tef_names = {s.name for s in signals.threat_event_frequency.signals}
        assert "attack_surface_breadth" in tef_names
        assert "public_exposure_history" in tef_names
        # No control-strength evidence from a passive scan.
        assert signals.control_strength.signals == []
        assert signals.confidence == "low"

    def test_iocs_increase_vulnerability_and_loss(self):
        result = DomainResult(
            target="https://compromised.example.com",
            ioc_findings=[
                IoCFinding(
                    ioc_type="credential_harvest",
                    description="Fake login form",
                    evidence="<form action='evil.com'>",
                    severity="critical",
                ),
                IoCFinding(
                    ioc_type="webshell_path",
                    description="Suspicious /shell.php reference",
                    evidence="/shell.php",
                    severity="high",
                ),
            ],
        )
        signals = compute_fair_signals(result, scan_mode="standard")
        assert any(s.name == "ioc_presence"
                   for s in signals.vulnerability.signals)
        assert any(s.name == "sensitive_data_iocs"
                   for s in signals.loss_magnitude.signals)

    def test_confidence_maps_to_scan_mode(self):
        r = DomainResult(target="https://m.example.com")
        assert compute_fair_signals(r, scan_mode="passive").confidence == "low"
        assert compute_fair_signals(r, scan_mode="lighttouch").confidence == "medium"
        assert compute_fair_signals(r, scan_mode="standard").confidence == "high"
        assert compute_fair_signals(r, scan_mode="full").confidence == "high"


# ---------------------------------------------------------------------------
# Integration — /scan/* orchestrators populate fair_signals
# ---------------------------------------------------------------------------

class TestFAIRIntegration:
    @patch("src.app.check_breaches", new_callable=AsyncMock)
    @patch("src.app.query_wayback", new_callable=AsyncMock)
    @patch("src.app.query_rdap", new_callable=AsyncMock)
    @patch("src.app.query_ct_logs", new_callable=AsyncMock)
    @patch("src.app.query_dns", new_callable=AsyncMock)
    def test_passive_scan_emits_fair_signals(
        self, mock_dns, mock_ct, mock_rdap, mock_wb, mock_breaches,
    ):
        mock_dns.return_value = DNSResult(
            domain="p.example.com", a_records=[ARecord(address="1.2.3.4")],
        )
        mock_ct.return_value = CTResult(
            domain="p.example.com",
            subdomains=["a.p.example.com", "b.p.example.com"],
            certificates_seen=3,
        )
        mock_rdap.return_value = RDAPResult(domain="p.example.com")
        mock_wb.return_value = WaybackResult(
            domain="p.example.com", snapshot_count=75,
        )
        mock_breaches.return_value = []

        resp = client.post(
            "/scan/passive", json={"targets": ["https://p.example.com"]},
        )
        assert resp.status_code == 200
        r = resp.json()["results"][0]
        assert r["fair_signals"] is not None
        assert r["fair_signals"]["scan_mode"] == "passive"
        assert r["fair_signals"]["confidence"] == "low"
        assert r["fair_signals"]["risk_tier"] in {"low", "medium", "high", "critical"}

    @patch("src.app.fetch_landing_page_full", new_callable=AsyncMock)
    @patch("src.app.check_ssl", new_callable=AsyncMock)
    def test_lighttouch_scan_emits_fair_signals_with_medium_confidence(
        self, mock_ssl, mock_fetch,
    ):
        mock_ssl.return_value = SSLCertResult(is_valid=True, grade="A")
        html = (
            "<html><head><title>Hello</title></head>"
            "<body>hi@example.com</body></html>"
        )
        mock_fetch.return_value = (
            {"server": "nginx/1.18.0"}, httpx.Cookies(), html,
        )
        resp = client.post(
            "/scan/lighttouch",
            json={"targets": ["https://lt.example.com"]},
        )
        assert resp.status_code == 200
        r = resp.json()["results"][0]
        assert r["fair_signals"] is not None
        assert r["fair_signals"]["scan_mode"] == "lighttouch"
        assert r["fair_signals"]["confidence"] == "medium"
