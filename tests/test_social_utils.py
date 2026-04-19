"""Tests for social platform detection."""

from src._social_utils import SOCIAL_PLATFORM_MAP, detect_platform


class TestDetectPlatform:
    def test_twitter(self):
        assert detect_platform("https://twitter.com/user") == "Twitter"

    def test_x_dot_com(self):
        assert detect_platform("https://x.com/user") == "Twitter/X"

    def test_linkedin(self):
        assert detect_platform("https://linkedin.com/in/user") == "LinkedIn"

    def test_github(self):
        assert detect_platform("https://github.com/user") == "GitHub"

    def test_facebook(self):
        assert detect_platform("https://facebook.com/page") == "Facebook"

    def test_instagram(self):
        assert detect_platform("https://instagram.com/user") == "Instagram"

    def test_www_prefix_stripped(self):
        assert detect_platform("https://www.github.com/user") == "GitHub"

    def test_unknown_domain_returns_empty(self):
        assert detect_platform("https://unknownsite.com/page") == ""

    def test_malformed_url_returns_empty(self):
        assert detect_platform("not a url at all") == ""

    def test_empty_string_returns_empty(self):
        assert detect_platform("") == ""

    def test_all_platforms_covered(self):
        for domain, name in SOCIAL_PLATFORM_MAP.items():
            result = detect_platform(f"https://{domain}/test")
            assert result == name, f"{domain} should map to {name}"
