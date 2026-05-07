"""Tests for the privacy compliance scanner."""

import pytest

from src.models import SensitivePathFinding, TechFinding
from src.privacy_scanner import analyze_privacy_compliance


def _path(path: str, status_code: int = 200) -> SensitivePathFinding:
    return SensitivePathFinding(
        path=path, url=f"https://example.com{path}",
        status_code=status_code, content_length=100,
        risk="", severity="info",
    )


def _tech(name: str, categories: list[str]) -> TechFinding:
    return TechFinding(name=name, categories=categories, confidence="high", evidence=[])


class TestAnalyzePrivacyCompliance:
    def test_full_compliance_gets_high_score(self):
        paths = [
            _path("/privacy-policy"),
            _path("/cookie-policy"),
            _path("/terms"),
            _path("/gdpr"),
            _path("/ccpa"),
            _path("/.well-known/dnt-policy.txt"),
        ]
        techs = [_tech("OneTrust", ["consent_management"])]
        result = analyze_privacy_compliance("example.com", paths, techs)
        assert result.score == 100
        assert result.grade == "A"
        assert result.consent_tool == "OneTrust"

    def test_no_compliance_gets_f(self):
        result = analyze_privacy_compliance("example.com", [], [])
        assert result.score == 0
        assert result.grade == "F"
        assert result.consent_tool == ""
        missing = [i for i in result.indicators if not i.present]
        assert len(missing) == 6

    def test_privacy_link_in_html(self):
        html = '<a href="/privacy-policy">Privacy Policy</a>'
        result = analyze_privacy_compliance("example.com", [], [], landing_html=html)
        pp = [i for i in result.indicators if i.name == "privacy_policy"]
        assert len(pp) == 1
        assert pp[0].present is True

    def test_do_not_sell_detected(self):
        html = '<a href="/opt-out">Do Not Sell My Personal Information</a>'
        result = analyze_privacy_compliance("example.com", [], [], landing_html=html)
        ccpa = [i for i in result.indicators if i.name == "ccpa_indicators"]
        assert len(ccpa) == 1
        assert ccpa[0].present is True

    def test_consent_tool_detection(self):
        techs = [_tech("Cookiebot", ["consent_management"])]
        result = analyze_privacy_compliance("example.com", [], techs)
        assert result.consent_tool == "Cookiebot"
        cc = [i for i in result.indicators if i.name == "cookie_consent_tool"]
        assert cc[0].present is True
        assert result.score >= 25

    def test_privacy_page_but_403_not_counted(self):
        paths = [_path("/privacy-policy", status_code=403)]
        result = analyze_privacy_compliance("example.com", paths, [])
        pp = [i for i in result.indicators if i.name == "privacy_policy"]
        assert pp[0].present is False

    def test_gdpr_indicators_with_consent_tool(self):
        paths = [_path("/cookie-policy")]
        techs = [_tech("OneTrust", ["consent_management"])]
        result = analyze_privacy_compliance("example.com", paths, techs)
        gdpr = [i for i in result.indicators if i.name == "gdpr_indicators"]
        assert gdpr[0].present is True
        assert len(gdpr[0].evidence) >= 2

    def test_grade_boundaries(self):
        result_0 = analyze_privacy_compliance("a.com", [], [])
        assert result_0.grade == "F"

        paths_25 = [_path("/privacy-policy")]
        result_25 = analyze_privacy_compliance("b.com", paths_25, [])
        assert result_25.grade == "D"

    def test_domain_in_result(self):
        result = analyze_privacy_compliance("test.io", [], [])
        assert result.domain == "test.io"
