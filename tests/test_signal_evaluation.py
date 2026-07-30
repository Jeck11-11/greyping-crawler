"""Section 18 required tests for the corrected FAIR signal generation +
scan-profile authority, plus the section 19 greyping.com fixture regression.

These lock in conservative classification: shared-CDN ports, robots/sitemap,
CDN-without-WAF, unassessed privacy, guessed-selector DKIM, and registered-only
typosquats must NOT inflate risk, while confirmed origin exposure and confirmed
phishing must.
"""

from __future__ import annotations

from src.fair_signals import compute_fair_signals
from src.signal_evaluation import (
    build_signal_evaluation,
    is_evidence_risk_eligible,
    report_confidence_for,
    resolve_scan_profile,
)
from src.easm_report import build_easm_report
from src.models import (
    ContactsGroup,
    DKIMResult,
    DMARCResult,
    DNSGroup,
    DNSResult,
    DomainResult,
    EmailFinding,
    EmailSecurityResult,
    OpenPort,
    PortScanResult,
    PrivacyComplianceResult,
    PrivacyIndicator,
    RobotsTxtResult,
    SecurityGroup,
    SecurityHeadersResult,
    SensitivePathFinding,
    SitemapResult,
    SPFResult,
    TyposquatCandidate,
    TyposquattingResult,
    WAFResult,
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _signal(signals, name):
    for factor in (signals.threat_event_frequency, signals.vulnerability,
                   signals.control_strength, signals.loss_magnitude):
        for s in factor.signals:
            if s.name == name:
                return s
    return None


def _names(signals):
    return {s.name for s in signals.all_signals}


def _shared_port(port, service):
    return OpenPort(
        port=port, service=service, banner="", is_risky=(port in (3389, 3306, 6379)),
        network_attribution="shared_cdn_edge", service_confirmed=False,
        origin_exposure_confirmed=False, affects_risk_score=False, confidence="low",
    )


# --------------------------------------------------------------------------- #
# Test 1 — passive scan profile
# --------------------------------------------------------------------------- #

class TestPassiveScanProfile:
    def test_passive_easm_never_reports_full_or_high_vuln(self):
        profile = resolve_scan_profile(scan_mode="full", nuclei_status="skipped")
        # Even the full crawl endpoint, with Nuclei skipped, is passive_easm.
        assert profile.scan_profile == "passive_easm"
        assert profile.active_vulnerability_scanning_included is False
        assert profile.active_vulnerability_scanning_completed is False
        assert "nuclei" in profile.modules_skipped
        # Coverage is never "full".
        assert profile.coverage_level != "full"

        rc = report_confidence_for(profile)
        assert rc.vulnerability_assessment_confidence != "high"
        assert rc.overall_report_confidence != "high"

        result = DomainResult(
            target="https://greyping.com",
            security=SecurityGroup(headers=SecurityHeadersResult(grade="D", score=30)),
        )
        report = build_easm_report(result, scan_mode="full", scan_profile=profile)
        assert report.scan_confidence != "high"
        assert report.executive_summary.scan_coverage != "full"
        narrative = report.executive_summary.narrative.lower()
        assert "active vulnerability testing" in narrative
        assert "not included" in narrative


# --------------------------------------------------------------------------- #
# Test 2 — shared Cloudflare ports
# --------------------------------------------------------------------------- #

class TestSharedCloudflarePorts:
    def _result(self):
        ports = [_shared_port(p, s) for p, s in (
            (80, "HTTP"), (443, "HTTPS"), (2082, "cPanel"), (2083, "cPanel-SSL"),
            (2086, "WHM"), (2087, "WHM-SSL"), (8080, "HTTP-Proxy"),
            (8443, "HTTPS-Alt"), (3389, "RDP"),
        )]
        return DomainResult(
            target="https://greyping.com",
            port_scan=PortScanResult(
                target="greyping.com", ip="104.16.0.1",
                network_attribution="shared_cdn_edge", cdn_provider="Cloudflare",
                open_ports=ports,
            ),
        )

    def test_shared_edge_ports_do_not_bear_risk(self):
        signals = compute_fair_signals(self._result(), scan_mode="full")
        names = _names(signals)
        assert "large_port_surface" not in names
        assert "exposed_services" not in names
        # Port hygiene must not be *reduced* by shared ports; it is unknown.
        hygiene = _signal(signals, "port_hygiene")
        assert hygiene is not None
        assert hygiene.status == "unknown"
        assert hygiene.affects_risk_score is False


# --------------------------------------------------------------------------- #
# Test 3 — confirmed origin RDP
# --------------------------------------------------------------------------- #

class TestConfirmedOriginRDP:
    def test_confirmed_origin_rdp_is_exposed_service(self):
        rdp = OpenPort(
            port=3389, service="RDP", banner="RDP\r\n", is_risky=True,
            network_attribution="origin", service_confirmed=True,
            origin_exposure_confirmed=True, affects_risk_score=True, confidence="high",
        )
        result = DomainResult(
            target="https://greyping.com",
            port_scan=PortScanResult(
                target="greyping.com", ip="203.0.113.10",
                network_attribution="origin", open_ports=[rdp],
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        svc = _signal(signals, "exposed_services")
        assert svc is not None
        assert svc.status == "confirmed"
        assert svc.signal_strength is not None and svc.signal_strength >= 60
        assert any("3389" in e for e in svc.evidence)


# --------------------------------------------------------------------------- #
# Test 4 — robots and sitemap
# --------------------------------------------------------------------------- #

class TestRobotsAndSitemap:
    def test_robots_sitemap_do_not_trigger_sensitive_paths(self):
        result = DomainResult(
            target="https://greyping.com",
            security=SecurityGroup(sensitive_paths=[
                SensitivePathFinding(path="/robots.txt", status_code=200, severity="low"),
                SensitivePathFinding(path="/sitemap.xml", status_code=200, severity="low"),
            ]),
            robots_txt=RobotsTxtResult(found=True, disallow_rules=["/", "/search"]),
            sitemap=SitemapResult(found=True, url_count=0, sitemap_parse_status="failed"),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        names = _names(signals)
        assert "sensitive_paths_exposed" not in names
        # sitemap_surface must be unknown, not a surface signal.
        sm = _signal(signals, "sitemap_surface")
        assert sm is not None and sm.status == "unknown"
        assert sm.affects_risk_score is False
        # robots.txt with only generic rules → no recon value.
        assert "robots_recon_value" not in names

    def test_robots_recon_value_only_for_useful_paths(self):
        result = DomainResult(
            target="https://greyping.com",
            robots_txt=RobotsTxtResult(found=True, disallow_rules=["/admin", "/api/internal"]),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        assert "robots_recon_value" in _names(signals)


# --------------------------------------------------------------------------- #
# Test 5 — CDN without confirmed WAF
# --------------------------------------------------------------------------- #

class TestCdnWithoutWaf:
    def test_cdn_only_not_scored_as_waf(self):
        result = DomainResult(
            target="https://greyping.com",
            waf=WAFResult(url="x", cdn_detected=True, cdn_provider="Cloudflare",
                          reverse_proxy_detected=True, waf_detected=None,
                          waf_detection_status="not_assessed"),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        sig = _signal(signals, "waf_or_cdn_detected")
        assert sig is not None
        assert sig.status == "inferred"
        assert sig.signal_strength is not None and sig.signal_strength <= 35
        assert "not confirmed" in sig.reason.lower() or "cdn only" in sig.reason.lower()
        # No confirmed WAF ruleset signal.
        assert "waf_ruleset_confirmed" not in _names(signals)


# --------------------------------------------------------------------------- #
# Test 6 — privacy not assessed
# --------------------------------------------------------------------------- #

class TestPrivacyNotAssessed:
    def test_privacy_unknown_no_grade_f_no_risk(self):
        result = DomainResult(
            target="https://greyping.com",
            privacy=PrivacyComplianceResult(
                domain="greyping.com", score=0, grade="F",
                consent_platform="not_detected",
                nonessential_tracking_before_consent="not_assessed",
                manual_validation_required=True,
                indicators=[PrivacyIndicator(name="privacy_policy", present=False)],
            ),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        sig = _signal(signals, "privacy_compliance_posture")
        assert sig is not None
        assert sig.status == "unknown"
        assert sig.signal_strength is None
        assert sig.affects_risk_score is False
        assert sig.risk_eligible is False


# --------------------------------------------------------------------------- #
# Test 7 — DKIM common-selector check
# --------------------------------------------------------------------------- #

class TestDkimCommonSelectors:
    def test_dkim_absence_is_inferred_not_confirmed(self):
        dkim = DKIMResult(selectors_checked=["default", "google", "selector1"],
                          selectors_found=[])
        assert dkim.confirmed_absent is False
        assert dkim.status == "not_observed_common_selectors"
        assert dkim.confidence <= 0.5

        es = EmailSecurityResult(
            domain="greyping.com",
            spf=SPFResult(exists=True, all_qualifier="~all"),
            dmarc=DMARCResult(exists=True, policy="none"),
            dkim=dkim,
        )
        result = DomainResult(
            target="https://greyping.com",
            dns=DNSGroup(records=DNSResult(domain="greyping.com"), email_security=es),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        sig = _signal(signals, "email_auth_missing")
        assert sig is not None
        # DMARC p=none is a confirmed weakness → overall confirmed, but DKIM
        # evidence is explicitly inferred.
        assert sig.status == "confirmed"
        assert any("inferred" in e.lower() for e in sig.evidence)


# --------------------------------------------------------------------------- #
# Test 8 — registered typosquat only
# --------------------------------------------------------------------------- #

class TestRegisteredTyposquatOnly:
    def test_registered_only_is_informational(self):
        typo = TyposquattingResult(
            domain="greyping.com",
            registered_candidates=[
                TyposquatCandidate(domain="greyp1ng.com", a_records=["1.2.3.4"]),
                TyposquatCandidate(domain="greypnig.com", a_records=["5.6.7.8"]),
            ],
        )
        result = DomainResult(target="https://greyping.com", typosquatting=typo)
        signals = compute_fair_signals(result, scan_mode="full")
        sig = _signal(signals, "typosquatting_exposure")
        assert sig is not None
        assert sig.status == "informational"
        assert sig.affects_risk_score is False
        assert sig.risk_eligible is False
        brand = _signal(signals, "brand_impersonation_risk")
        assert brand is not None and brand.affects_risk_score is False


# --------------------------------------------------------------------------- #
# Test 9 — confirmed phishing domain
# --------------------------------------------------------------------------- #

class TestConfirmedPhishingDomain:
    def test_confirmed_phishing_raises_risk(self):
        cand = TyposquatCandidate(
            domain="greyping-login.com", a_records=["9.9.9.9"],
            state="confirmed_phishing", website_active=True, mail_configured=True,
            brand_content_detected=True, login_clone_detected=True,
            malicious_reputation=True,
        )
        result = DomainResult(
            target="https://greyping.com",
            typosquatting=TyposquattingResult(domain="greyping.com",
                                              registered_candidates=[cand]),
        )
        signals = compute_fair_signals(result, scan_mode="full")
        sig = _signal(signals, "typosquatting_exposure")
        assert sig is not None
        assert sig.status == "confirmed"
        assert sig.signal_strength is not None and sig.signal_strength >= 70
        assert sig.affects_risk_score is True
        brand = _signal(signals, "brand_impersonation_risk")
        assert brand is not None and brand.affects_risk_score is True


# --------------------------------------------------------------------------- #
# Test 10 — idempotency
# --------------------------------------------------------------------------- #

class TestIdempotency:
    def _result(self):
        return DomainResult(
            target="https://greyping.com",
            security=SecurityGroup(headers=SecurityHeadersResult(grade="D", score=30)),
            waf=WAFResult(url="x", cdn_detected=True, cdn_provider="Cloudflare",
                          waf_detected=None, waf_detection_status="not_assessed"),
            typosquatting=TyposquattingResult(
                domain="greyping.com",
                registered_candidates=[TyposquatCandidate(domain="greyp1ng.com",
                                                          a_records=["1.2.3.4"])],
            ),
        )

    def test_repeated_evaluation_is_stable(self):
        profile = resolve_scan_profile(scan_mode="full", nuclei_status="skipped")
        r1 = self._result()
        r2 = self._result()
        e1 = build_signal_evaluation(compute_fair_signals(r1, scan_mode="full"), profile)
        e2 = build_signal_evaluation(compute_fair_signals(r2, scan_mode="full"), profile)

        c1 = [c.signal_code for c in e1.candidate_signals]
        c2 = [c.signal_code for c in e2.candidate_signals]
        assert c1 == c2
        # No duplicate candidate signal codes.
        assert len(c1) == len(set(c1))
        # Stable evidence fingerprints.
        fp1 = [ev.fingerprint for c in e1.candidate_signals for ev in c.evidence]
        fp2 = [ev.fingerprint for c in e2.candidate_signals for ev in c.evidence]
        assert fp1 == fp2


# --------------------------------------------------------------------------- #
# Central eligibility gate
# --------------------------------------------------------------------------- #

class TestEligibilityGate:
    def test_shared_cdn_edge_excluded_with_reason(self):
        out = is_evidence_risk_eligible({
            "affects_risk_score": False,
            "exclusion_reason": "Shared CDN edge; origin exposure not confirmed",
        })
        assert out["eligible"] is False
        assert "Shared CDN edge" in out["reason"]

    def test_confirmed_origin_eligible(self):
        out = is_evidence_risk_eligible({
            "affects_risk_score": True, "origin_required": True,
            "origin_exposure_confirmed": True,
        })
        assert out["eligible"] is True

    def test_low_confidence_excluded(self):
        out = is_evidence_risk_eligible({"confidence": 0.2, "min_confidence": 0.6})
        assert out["eligible"] is False


# --------------------------------------------------------------------------- #
# Section 19 — greyping.com fixture regression
# --------------------------------------------------------------------------- #

class TestGreypingFixtureRegression:
    """Reproduces the reported greyping.com contradictions and asserts the fix."""

    def _greyping(self):
        # 9 Cloudflare shared-edge ports, robots + empty sitemap, CDN no WAF,
        # unassessed privacy, DMARC p=none + guessed-selector DKIM, two
        # registered-only lookalikes.
        ports = [_shared_port(p, s) for p, s in (
            (80, "HTTP"), (443, "HTTPS"), (2052, "HTTP"), (2053, "HTTPS"),
            (2082, "cPanel"), (2083, "cPanel-SSL"), (2086, "WHM"),
            (2087, "WHM-SSL"), (8443, "HTTPS-Alt"),
        )]
        es = EmailSecurityResult(
            domain="greyping.com",
            spf=SPFResult(exists=True, all_qualifier="~all"),
            dmarc=DMARCResult(exists=True, policy="none"),
            dkim=DKIMResult(selectors_checked=["default", "google"], selectors_found=[]),
        )
        return DomainResult(
            target="https://greyping.com",
            security=SecurityGroup(
                headers=SecurityHeadersResult(grade="C", score=55),
                sensitive_paths=[
                    SensitivePathFinding(path="/robots.txt", status_code=200, severity="low"),
                    SensitivePathFinding(path="/sitemap.xml", status_code=200, severity="low"),
                ],
            ),
            dns=DNSGroup(records=DNSResult(domain="greyping.com"), email_security=es),
            contacts=ContactsGroup(emails=[EmailFinding(email="hi@greyping.com", found_on=["x"])]),
            port_scan=PortScanResult(
                target="greyping.com", ip="104.16.0.1",
                network_attribution="shared_cdn_edge", cdn_provider="Cloudflare",
                open_ports=ports,
            ),
            waf=WAFResult(url="x", cdn_detected=True, cdn_provider="Cloudflare",
                          reverse_proxy_detected=True, waf_detected=None,
                          waf_detection_status="not_assessed"),
            privacy=PrivacyComplianceResult(
                domain="greyping.com", score=0, grade="F",
                consent_platform="not_detected", manual_validation_required=True,
                indicators=[PrivacyIndicator(name="privacy_policy", present=False)],
            ),
            robots_txt=RobotsTxtResult(found=True, disallow_rules=["/"]),
            sitemap=SitemapResult(found=True, url_count=0, sitemap_parse_status="failed"),
            typosquatting=TyposquattingResult(
                domain="greyping.com",
                registered_candidates=[
                    TyposquatCandidate(domain="greyp1ng.com", a_records=["1.2.3.4"]),
                    TyposquatCandidate(domain="greyplng.com", a_records=["5.6.7.8"]),
                ],
            ),
        )

    def test_fixture_expected_highlevel_result(self):
        result = self._greyping()
        profile = resolve_scan_profile(scan_mode="full", nuclei_status="skipped")
        result.scan_profile = profile
        signals = compute_fair_signals(result, scan_mode="full", scan_profile=profile)
        names = _names(signals)
        evaluation = build_signal_evaluation(signals, profile)
        report = build_easm_report(result, scan_mode="full", scan_profile=profile)

        # scan profile / coverage
        assert profile.scan_profile == "passive_easm"
        assert profile.active_vulnerability_scanning_included is False
        assert report.executive_summary.scan_coverage != "full"
        assert report.scan_confidence != "high"

        # no shared-CDN port inflation
        assert "large_port_surface" not in names
        assert "exposed_services" not in names

        # robots/sitemap
        assert "sensitive_paths_exposed" not in names
        assert "robots_recon_value" not in names          # only "/" disallow
        assert _signal(signals, "sitemap_surface").status == "unknown"

        # CDN confirmed, WAF unknown
        waf_sig = _signal(signals, "waf_or_cdn_detected")
        assert waf_sig.status == "inferred" and waf_sig.signal_strength <= 35
        assert "waf_ruleset_confirmed" not in names

        # privacy unknown
        assert _signal(signals, "privacy_compliance_posture").status == "unknown"

        # DMARC weakness confirmed, DKIM inferred only
        email = _signal(signals, "email_auth_missing")
        assert email.status == "confirmed"
        assert any("inferred" in e.lower() for e in email.evidence)

        # registered lookalikes informational, not an exploit chain
        assert _signal(signals, "typosquatting_exposure").affects_risk_score is False
        assert "attack_path_chains" not in names or \
            _signal(signals, "attack_path_chains").status != "confirmed"

        # scanner weights / totals marked non-authoritative
        assert signals.authoritative is False
        assert signals.scoring_authority == "downstream_xano"
        assert evaluation.scoring_authority == "downstream_xano"

        # financial estimates are not produced by the scanner
        assert report.financial_impact.financial_impact_status in (
            "insufficient_data", "requires_business_inputs")

        # the shared ports live as excluded/informational, not candidate risk
        cand_codes = {c.signal_code for c in evaluation.candidate_signals}
        assert "large_port_surface" not in cand_codes
        assert "exposed_services" not in cand_codes
