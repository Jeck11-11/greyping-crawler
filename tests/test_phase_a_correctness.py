"""Phase A correctness fixes — acceptance tests.

Covers spec Tests 1 (nuclei skipped), 2 (failed screenshot), 11 (contact/social
dedup), and 12 (sitemap partial reporting).
"""

from __future__ import annotations

from src.extractors import classify_social_url, normalize_phone_e164
from src.module_status import nuclei_module_status
from src.robots_sitemap import parse_sitemap_xml
from src.models import ScreenshotResult
from src.app import _screenshot_succeeded


# --------------------------------------------------------------------------
# Test 1 — Nuclei intentionally excluded
# --------------------------------------------------------------------------

class TestNucleiSkipped:
    def test_skipped_is_intentional_not_a_pass(self):
        mod = nuclei_module_status("skipped", scan_profile="passive_easm")
        assert mod.status == "skipped"
        assert mod.intentional is True
        assert mod.included_in_scan_profile is False
        assert mod.findings_count is None          # not 0 — no "clean pass"
        assert mod.successful is False
        assert "intentionally" in mod.message.lower()

    def test_skipped_not_marked_failed(self):
        mod = nuclei_module_status("skipped")
        assert mod.status != "failed"
        assert mod.error is None

    def test_completed_profile_still_ok_without_nuclei(self):
        # The passive scan is complete for its profile; nuclei absence != failure.
        mod = nuclei_module_status("skipped")
        assert mod.status == "skipped" and mod.applicable is True


# --------------------------------------------------------------------------
# Test 2 — Failed screenshot counts as an attempt, not a success
# --------------------------------------------------------------------------

class TestScreenshotCounting:
    def test_empty_failed_screenshot_not_taken(self):
        ss = ScreenshotResult(
            url="https://x.example",
            image_base64="",
            width=0,
            height=0,
            size_bytes=0,
            error="Playwright not available",
        )
        assert _screenshot_succeeded(ss) is False

    def test_real_screenshot_counts(self):
        ss = ScreenshotResult(
            url="https://x.example",
            image_base64="aGVsbG8=",
            width=1280,
            height=720,
            size_bytes=5000,
            error=None,
        )
        assert _screenshot_succeeded(ss) is True


# --------------------------------------------------------------------------
# Test 11 — Contact & social dedup
# --------------------------------------------------------------------------

class TestContactDedup:
    def test_phone_variants_normalize_to_same_e164(self):
        a = normalize_phone_e164("+35316510300", "353", "IE")
        b = normalize_phone_e164("353 1 6510 300", "353", "IE")
        assert a["normalized_value"] == b["normalized_value"] == "+35316510300"

    def test_national_number_uses_default_region(self):
        r = normalize_phone_e164("01 6510 300", "353", "IE")
        assert r["normalized_value"] == "+3531 6510 300".replace(" ", "")
        assert r["country"] == "IE"
        assert r["confidence"] == "high"

    def test_bare_fragment_is_low_confidence(self):
        r = normalize_phone_e164("1 651 0300")  # no region context
        assert r["confidence"] == "low"

    def test_share_links_not_profiles(self):
        assert classify_social_url("https://facebook.com/sharer/sharer.php?u=x") == "share_link"
        assert classify_social_url("https://twitter.com/intent/tweet?text=x") == "share_link"
        assert classify_social_url("https://www.pinterest.com/pin/create/button/?url=x") == "share_link"
        assert classify_social_url("https://t.co/abc123") == "tracking_link"

    def test_real_profile_is_profile(self):
        assert classify_social_url("https://www.linkedin.com/company/acme") == "organisation_profile"
        assert classify_social_url("https://twitter.com/acmecorp") == "organisation_profile"


# --------------------------------------------------------------------------
# Test 12 — Sitemap index reported as partial, not empty
# --------------------------------------------------------------------------

class TestSitemapReporting:
    def test_sitemap_index_is_partial(self):
        xml = """<?xml version="1.0"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <sitemap><loc>https://e.com/sitemap1.xml</loc></sitemap>
          <sitemap><loc>https://e.com/sitemap2.xml</loc></sitemap>
        </sitemapindex>"""
        r = parse_sitemap_xml(xml)
        assert r.found is True
        assert r.sitemap_indexes_found == 1
        assert r.nested_sitemaps_found == 2
        assert r.sitemap_urls_extracted == 0
        assert r.sitemap_parse_status == "partial"

    def test_leaf_sitemap_is_complete(self):
        xml = """<?xml version="1.0"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
          <url><loc>https://e.com/a</loc></url>
          <url><loc>https://e.com/b</loc></url>
        </urlset>"""
        r = parse_sitemap_xml(xml)
        assert r.sitemap_urls_extracted == 2
        assert r.sitemap_parse_status == "complete"

    def test_empty_sitemap(self):
        r = parse_sitemap_xml("")
        assert r.sitemap_parse_status == "empty"
