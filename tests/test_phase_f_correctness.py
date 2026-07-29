"""Phase F — residual defensibility fixes surfaced by a live greyping.com scan.

CT-log markdown artifact, WAF-vs-CDN wiring, affects_risk_score consistency,
attack-path severity alignment, placeholder-email filtering, sitemap empty.
"""

from __future__ import annotations

from src.passive_intel import _clean_hostname, _organizational_domain
from src.extractors import _is_placeholder_email, extract_contacts
from src.robots_sitemap import parse_sitemap_xml
from src.attack_paths import analyze_attack_paths
from src.easm_report import build_easm_report
from src.models import (
    DomainResult,
    DNSGroup,
    DNSResult,
    EmailFinding,
    EmailSecurityResult,
    DMARCResult,
    SPFResult,
    ContactsGroup,
    FindingClassification,
    SecurityGroup,
    SecurityHeadersResult,
    WAFResult,
    IPEnrichmentResult,
)
from bs4 import BeautifulSoup


def _soup(html):
    return BeautifulSoup(html, "html.parser")


# 1. CT-log markdown artifact
class TestHostnameCleaning:
    def test_markdown_link_unwrapped(self):
        assert _clean_hostname("[www.greyping.com](https://www.greyping.com)") == "www.greyping.com"

    def test_wildcard_and_scheme_stripped(self):
        assert _clean_hostname("*.greyping.com") == "greyping.com"
        assert _clean_hostname("https://mail.greyping.com/") == "mail.greyping.com"

    def test_garbage_rejected(self):
        assert _clean_hostname("not a hostname") == ""
        assert _clean_hostname("") == ""

    def test_c99_markdown_unwrapped_without_backreference(self):
        # C99's subdomainfinder returns each subdomain as a markdown link. The
        # unwrap must not rely on a "\1" backreference string (which failed to
        # expand under the Alpine container runtime) — assert the capture-group
        # replacement leaves a bare hostname.
        from src.c99_client import _MARKDOWN_LINK_RE
        raw = "[www.greyping.com](https://www.greyping.com)"
        cleaned = _MARKDOWN_LINK_RE.sub(lambda m: m.group(1), raw)
        assert cleaned == "www.greyping.com"
        assert "[" not in cleaned and "](" not in cleaned


# 3. affects_risk_score consistency
class TestAffectsRiskScoreConsistency:
    def test_informational_and_candidates_do_not_affect_score(self):
        result = DomainResult(
            target="https://greyping.com",
            security=SecurityGroup(headers=SecurityHeadersResult(grade="D")),
        )
        report = build_easm_report(result)
        for f in report.prioritized_findings:
            if f.affects_risk_score:
                assert f.classification == FindingClassification.confirmed_issue
                assert f.severity in ("critical", "high", "medium", "low")
        # And excluded_inputs must contain every non-scoring finding.
        excluded_ids = {e.split(":")[0] for e in report.excluded_inputs}
        for f in report.prioritized_findings:
            if not f.affects_risk_score:
                assert f.id in excluded_ids


# 2. WAF vs CDN — CDN from ASN, WAF stays not_assessed
class TestWafCdnSeparation:
    def test_cdn_present_waf_not_asserted(self):
        waf = WAFResult(url="x", detected=False, cdn_detected=True,
                        cdn_provider="Cloudflare", reverse_proxy_detected=True,
                        waf_detected=None, waf_detection_status="not_assessed")
        result = DomainResult(target="https://greyping.com", waf=waf)
        report = build_easm_report(result)
        rw = report.ransomware_susceptibility
        # Mitigations may cite CDN, but must not assert a WAF ruleset.
        joined = " ".join(rw.mitigations).lower()
        assert "waf enabled" not in joined
        if "cdn" in joined:
            assert "ruleset not confirmed" in joined


# 4. attack-path severity aligns with DMARC state
class TestAttackPathDmarcSeverity:
    def _result(self, policy):
        es = EmailSecurityResult(
            domain="greyping.com",
            spf=SPFResult(exists=True, all_qualifier="~all"),
            dmarc=DMARCResult(exists=(policy is not None), policy=policy),
        )
        return DomainResult(
            target="https://greyping.com",
            dns=DNSGroup(records=DNSResult(domain="greyping.com"), email_security=es),
            contacts=ContactsGroup(emails=[EmailFinding(email="a@greyping.com", found_on=["x"])]),
        )

    def test_p_none_is_medium_not_high(self):
        res = analyze_attack_paths(self._result("none"))
        dmarc_paths = [p for p in res.paths if "DMARC" in p.title]
        assert dmarc_paths and dmarc_paths[0].severity == "medium"
        assert dmarc_paths[0].likelihood == "possible"

    def test_missing_dmarc_is_high(self):
        res = analyze_attack_paths(self._result(None))
        dmarc_paths = [p for p in res.paths if "DMARC" in p.title]
        assert dmarc_paths and dmarc_paths[0].severity == "high"


# 5. placeholder emails
class TestPlaceholderEmail:
    def test_example_domain_filtered(self):
        assert _is_placeholder_email("contact@example.com") is True
        assert _is_placeholder_email("sales@acme.com") is False

    def test_extract_drops_placeholder(self):
        html = '<a href="mailto:contact@example.com">x</a><p>real@acme.io</p>'
        contacts = extract_contacts(_soup(html), html)
        assert "contact@example.com" not in contacts.emails
        assert "real@acme.io" in contacts.emails


# 6. empty sitemap
class TestSitemapEmpty:
    def test_blank_body_is_empty_not_failed(self):
        assert parse_sitemap_xml("   ").sitemap_parse_status == "empty"

    def test_real_garbage_is_failed(self):
        assert parse_sitemap_xml("<this is not valid xml at all >>>").sitemap_parse_status == "failed"
