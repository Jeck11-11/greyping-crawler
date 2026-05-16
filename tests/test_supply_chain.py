"""Tests for third-party supply chain risk analysis."""

from src.supply_chain import (
    analyze_supply_chain,
    _check_vulnerable,
    _classify_provider,
    _is_external,
    _parse_version,
    _version_lt,
)


class TestVersionComparison:
    def test_version_lt_simple(self):
        assert _version_lt("3.3.1", "3.5.0")
        assert not _version_lt("3.5.0", "3.5.0")
        assert not _version_lt("3.6.0", "3.5.0")

    def test_version_lt_patch(self):
        assert _version_lt("4.17.10", "4.17.21")
        assert not _version_lt("4.17.21", "4.17.21")

    def test_parse_version(self):
        assert _parse_version("3.5.0") == (3, 5, 0)
        assert _parse_version("10.4.1") == (10, 4, 1)


class TestVulnerableLibraryDetection:
    def test_jquery_vulnerable(self):
        lib, ver, cve, sev = _check_vulnerable(
            "https://cdnjs.cloudflare.com/ajax/libs/jquery-3.3.1.min.js"
        )
        assert lib == "jQuery"
        assert ver == "3.3.1"
        assert cve == "CVE-2020-11022"

    def test_jquery_safe(self):
        lib, ver, cve, sev = _check_vulnerable(
            "https://cdn.jsdelivr.net/npm/jquery-3.7.1.min.js"
        )
        assert lib == "jQuery"
        assert ver == "3.7.1"
        assert cve == ""

    def test_lodash_vulnerable(self):
        lib, ver, cve, sev = _check_vulnerable(
            "https://cdn.jsdelivr.net/npm/lodash-4.17.10.min.js"
        )
        assert lib == "Lodash"
        assert ver == "4.17.10"
        assert cve == "CVE-2021-23337"

    def test_angular_vulnerable(self):
        lib, ver, cve, sev = _check_vulnerable(
            "https://ajax.googleapis.com/ajax/libs/angular.min-1.6.9.js"
        )
        assert lib == "AngularJS"
        assert ver == "1.6.9"
        assert "CVE" in cve

    def test_unknown_script_not_vulnerable(self):
        lib, ver, cve, sev = _check_vulnerable(
            "https://cdn.example.com/custom-app-2.0.1.js"
        )
        assert lib == ""
        assert cve == ""

    def test_jquery_at_sign_separator(self):
        lib, ver, cve, sev = _check_vulnerable(
            "https://cdn.jsdelivr.net/npm/jquery@3.3.1/dist/jquery.min.js"
        )
        assert lib == "jQuery"
        assert ver == "3.3.1"
        assert cve == "CVE-2020-11022"


class TestSRIDetection:
    def test_sri_present(self):
        html = """
        <html><head>
        <script src="https://cdn.jsdelivr.net/npm/lodash-4.17.21.min.js"
                integrity="sha384-abc123" crossorigin="anonymous"></script>
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.resources[0].has_sri is True
        assert result.scripts_without_sri == 0

    def test_sri_absent_flagged(self):
        html = """
        <html><head>
        <script src="https://cdn.jsdelivr.net/npm/lodash-4.17.21.min.js"></script>
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.resources[0].has_sri is False
        assert result.scripts_without_sri == 1
        assert any("SRI" in i for i in result.resources[0].issues)


class TestCDNClassification:
    def test_jsdelivr(self):
        assert _classify_provider("cdn.jsdelivr.net") == "jsDelivr"

    def test_cdnjs(self):
        assert _classify_provider("cdnjs.cloudflare.com") == "Cloudflare CDNJS"

    def test_googleapis(self):
        assert _classify_provider("ajax.googleapis.com") == "Google Hosted Libraries"

    def test_cloudfront(self):
        assert _classify_provider("d1234.cloudfront.net") == "AWS CloudFront"

    def test_unknown_provider(self):
        assert _classify_provider("sketchy-cdn.example.org") == "unknown"


class TestInternalExternal:
    def test_same_domain_is_internal(self):
        assert not _is_external("https://example.com/app.js", "example.com")

    def test_subdomain_is_internal(self):
        assert not _is_external("https://cdn.example.com/app.js", "example.com")

    def test_different_domain_is_external(self):
        assert _is_external("https://cdn.jsdelivr.net/npm/vue.js", "example.com")

    def test_www_stripped(self):
        assert not _is_external("https://www.example.com/app.js", "www.example.com")


class TestResourceExtraction:
    def test_extracts_external_scripts(self):
        html = """
        <html><head>
        <script src="https://cdn.jsdelivr.net/npm/vue.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/lodash.js"></script>
        <script src="/static/app.js"></script>
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.total_external_resources == 2

    def test_extracts_stylesheets(self):
        html = """
        <html><head>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.total_external_resources == 1
        assert result.resources[0].resource_type == "stylesheet"
        assert result.resources[0].provider == "jsDelivr"

    def test_internal_resources_excluded(self):
        html = """
        <html><head>
        <script src="/static/app.js"></script>
        <script src="https://example.com/main.js"></script>
        <link rel="stylesheet" href="/style.css">
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.total_external_resources == 0

    def test_empty_html_returns_none(self):
        assert analyze_supply_chain(None, "https://example.com") is None
        assert analyze_supply_chain("", "https://example.com") is None


class TestRiskSummary:
    def test_high_when_vulnerable_lib(self):
        html = """
        <html><head>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery-3.3.1.min.js"></script>
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.risk_summary == "high"
        assert result.vulnerable_libraries == 1

    def test_high_when_compromised_provider(self):
        html = """
        <html><head>
        <script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.risk_summary == "high"
        assert any("COMPROMISED" in i for i in result.issues)

    def test_medium_when_no_sri(self):
        html = """
        <html><head>
        <script src="https://cdn.jsdelivr.net/npm/some-lib.js"></script>
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.risk_summary == "medium"

    def test_none_when_no_external(self):
        html = """
        <html><head>
        <script src="/static/app.js"></script>
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.risk_summary == "none"
        assert result.total_external_resources == 0

    def test_info_when_all_have_sri(self):
        html = """
        <html><head>
        <script src="https://cdn.jsdelivr.net/npm/vue@3.3.0/dist/vue.min.js"
                integrity="sha384-xyz" crossorigin="anonymous"></script>
        </head></html>
        """
        result = analyze_supply_chain(html, "https://example.com")
        assert result is not None
        assert result.risk_summary == "none"
        assert result.scripts_without_sri == 0
