"""Regression locks for the accuracy-cleanup PR (items 1-5), keyed to the live
zirona.ie scan that surfaced them. Values mirror that scan.

1 HSTS: includeSubDomains present must not be re-recommended; the short
  max-age weakness must reach the EASM findings.
2 Cache-Control: missing on a public page is a hardening recommendation, not a
  scoring confirmed_issue.
3 Server: a Cloudflare Server header is platform-owned, not customer-owned.
4 Typosquat: each lookalike gets a distinct finding fingerprint.
5 Sensitive paths: robots.txt / sitemap.xml are not sensitive paths, but remain
  in recon_artifacts.
"""

from __future__ import annotations

from src.security_headers import _check_hsts, analyze_headers
from src.path_scanner import _SENSITIVE_PATHS, _INFO_PATHS
from src.easm_report import build_easm_report
from src.models import (
    DomainResult,
    FindingClassification,
    FindingOwner,
    HeaderFinding,
    RobotsTxtResult,
    SecurityGroup,
    SecurityHeadersResult,
    SensitivePathFinding,
    SitemapResult,
    TyposquatCandidate,
    TyposquattingResult,
)


def _finding(report, fid):
    return next((f for f in report.prioritized_findings if f.id == fid), None)


# --------------------------------------------------------------------------- #
# Item 1 — HSTS
# --------------------------------------------------------------------------- #

class TestHstsHandling:
    def test_includesubdomains_present_not_re_recommended(self):
        # zirona sent lowercase "includeSubdomains" — must be detected.
        status, rec = _check_hsts("max-age=15768000;includeSubdomains")
        assert status == "weak"                       # short max-age is still weak
        assert "182d" in rec or "15768000" in rec     # genuine weakness reported
        assert "includesubdomains" not in rec.lower() # not told to add what's present

    def test_includesubdomains_absent_is_recommended(self):
        status, rec = _check_hsts("max-age=15768000")
        assert status == "weak"
        assert "includesubdomains" in rec.lower()

    def test_strong_hsts_is_present(self):
        status, rec = _check_hsts("max-age=31536000; includeSubDomains")
        assert status == "present" and rec == ""

    def test_weak_hsts_surfaces_in_easm_findings(self):
        headers = analyze_headers({
            "Strict-Transport-Security": "max-age=15768000;includeSubdomains",
        })
        result = DomainResult(target="https://zirona.ie",
                              security=SecurityGroup(headers=headers))
        report = build_easm_report(result, scan_mode="full")
        weak = _finding(report, "weak_strict_transport_security")
        assert weak is not None, "short-max-age HSTS must reach the EASM findings"
        assert weak.classification == FindingClassification.confirmed_issue
        assert weak.affects_risk_score is True
        assert any("max-age" in e.lower() for e in weak.evidence)


# --------------------------------------------------------------------------- #
# Item 2 — Cache-Control
# --------------------------------------------------------------------------- #

class TestCacheControlClassification:
    def _report_for_cache(self, status, value=""):
        headers = SecurityHeadersResult(grade="D", score=59, findings=[
            HeaderFinding(header="Cache-Control", status=status, value=value,
                          recommendation="Add 'Cache-Control: no-store'…", severity="low"),
        ])
        result = DomainResult(target="https://zirona.ie",
                              security=SecurityGroup(headers=headers))
        return build_easm_report(result, scan_mode="full")

    def test_missing_cache_control_is_not_a_scoring_issue(self):
        report = self._report_for_cache("missing")
        f = _finding(report, "missing_cache_control")
        assert f is not None
        assert f.classification == FindingClassification.hardening_recommendation
        assert f.affects_risk_score is False
        # It must NOT count as a confirmed, score-affecting issue.
        assert f.id not in {s.split(" ")[0] for s in report.score_inputs}


# --------------------------------------------------------------------------- #
# Item 3 — Cloudflare Server ownership
# --------------------------------------------------------------------------- #

class TestServerOwnership:
    def test_cloudflare_server_is_platform_owned(self):
        headers = SecurityHeadersResult(grade="D", score=59, server="cloudflare", findings=[
            HeaderFinding(header="Server", status="present", value="cloudflare",
                          recommendation="Remove or obfuscate…", severity="low"),
        ])
        result = DomainResult(target="https://zirona.ie",
                              security=SecurityGroup(headers=headers))
        report = build_easm_report(result, scan_mode="full")
        f = _finding(report, "info_leak_server")
        assert f is not None
        assert f.owner == FindingOwner.platform
        assert f.classification == FindingClassification.platform_behavior
        assert f.affects_risk_score is False

    def test_custom_server_stays_customer_owned(self):
        headers = SecurityHeadersResult(grade="D", score=59, server="Apache/2.4.1", findings=[
            HeaderFinding(header="Server", status="present", value="Apache/2.4.1",
                          recommendation="Remove…", severity="low"),
        ])
        result = DomainResult(target="https://x.example",
                              security=SecurityGroup(headers=headers))
        f = _finding(build_easm_report(result, scan_mode="full"), "info_leak_server")
        assert f is not None and f.owner == FindingOwner.customer


# --------------------------------------------------------------------------- #
# Item 4 — typosquat fingerprints
# --------------------------------------------------------------------------- #

class TestTyposquatFingerprints:
    def test_each_lookalike_has_a_distinct_fingerprint(self):
        typo = TyposquattingResult(domain="zirona.ie", registered_candidates=[
            TyposquatCandidate(domain="zirona.com", a_records=["13.248.169.48"], technique="tld_swap"),
            TyposquatCandidate(domain="zirona.org", a_records=["35.176.193.99"], technique="tld_swap"),
            TyposquatCandidate(domain="sirona.ie", a_records=["78.153.218.44"], technique="homoglyph"),
        ])
        result = DomainResult(target="https://zirona.ie", typosquatting=typo)
        report = build_easm_report(result, scan_mode="full")
        typo_findings = [f for f in report.prioritized_findings if f.id == "typosquat_domains_found"]
        assert len(typo_findings) == 3
        fps = {f.fingerprint for f in typo_findings}
        assert len(fps) == 3, "each lookalike domain must have a unique fingerprint"


# --------------------------------------------------------------------------- #
# Item 5 — sensitive-path counting
# --------------------------------------------------------------------------- #

class TestSensitivePathCounting:
    def test_robots_and_sitemap_are_not_sensitive_paths(self):
        probed = {p[0] for p in _SENSITIVE_PATHS}
        assert "/robots.txt" not in probed
        assert "/sitemap.xml" not in probed
        assert "/robots.txt" not in _INFO_PATHS
        assert "/sitemap.xml" not in _INFO_PATHS
        # privacy/terms discovery paths must remain (privacy scanner depends on them)
        assert "/privacy" in _INFO_PATHS and "/terms" in _INFO_PATHS

    def test_recon_artifacts_still_report_robots_and_sitemap(self):
        result = DomainResult(
            target="https://zirona.ie",
            security=SecurityGroup(sensitive_paths=[]),  # no robots/sitemap here anymore
            robots_txt=RobotsTxtResult(found=True, disallow_rules=["/wp-admin/"]),
            sitemap=SitemapResult(found=True, url_count=15, sitemap_parse_status="complete"),
        )
        report = build_easm_report(result, scan_mode="full")
        recon_paths = {a.path for a in report.recon_artifacts}
        assert "/robots.txt" in recon_paths
        assert "/sitemap.xml" in recon_paths
        # …and they are not counted as sensitive-path findings
        assert not any(a.path in ("/robots.txt", "/sitemap.xml")
                       for a in result.security.sensitive_paths)

    def test_genuine_sensitive_path_still_counts(self):
        result = DomainResult(
            target="https://x.example",
            security=SecurityGroup(sensitive_paths=[
                SensitivePathFinding(path="/.env", status_code=200, content_length=120,
                                     risk="Environment file exposed.", severity="critical"),
            ]),
        )
        report = build_easm_report(result, scan_mode="full")
        assert any(f.source_field == "sensitive_paths" or "/.env" in " ".join(f.evidence)
                   for f in report.prioritized_findings)
