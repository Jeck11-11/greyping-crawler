"""Tests for target validation and SSRF protection."""

from unittest.mock import patch

import pytest

from src._http_utils import TargetValidationError, normalise_target, validate_target


class TestValidateTarget:
    def test_normal_domain_passes(self):
        assert validate_target("example.com") == "https://example.com"

    def test_https_url_passes(self):
        assert validate_target("https://google.com") == "https://google.com"

    def test_http_url_passes(self):
        assert validate_target("http://example.com") == "http://example.com"

    def test_empty_string_raises(self):
        with pytest.raises(TargetValidationError, match="Empty"):
            validate_target("")

    def test_whitespace_only_raises(self):
        with pytest.raises(TargetValidationError, match="Empty"):
            validate_target("   ")

    def test_file_scheme_blocked(self):
        with pytest.raises(TargetValidationError, match="Blocked scheme"):
            validate_target("file:///etc/passwd")

    def test_ftp_scheme_blocked(self):
        with pytest.raises(TargetValidationError, match="Blocked scheme"):
            validate_target("ftp://evil.com")

    def test_data_scheme_blocked(self):
        with pytest.raises(TargetValidationError, match="Blocked scheme"):
            validate_target("data:text/html,<h1>hi</h1>")

    def test_localhost_blocked(self):
        with pytest.raises(TargetValidationError, match="Loopback"):
            validate_target("localhost")

    def test_127_0_0_1_blocked(self):
        with pytest.raises(TargetValidationError, match="Loopback"):
            validate_target("127.0.0.1")

    def test_ipv6_loopback_blocked(self):
        with pytest.raises(TargetValidationError):
            validate_target("::1")

    def test_ipv6_loopback_bracketed_blocked(self):
        with pytest.raises(TargetValidationError, match="Loopback"):
            validate_target("[::1]")

    def test_private_ip_blocked(self):
        with pytest.raises(TargetValidationError, match="Private"):
            validate_target("192.168.1.1")

    def test_10_net_blocked(self):
        with pytest.raises(TargetValidationError, match="Private"):
            validate_target("10.0.0.1")

    def test_dns_rebinding_blocked(self):
        fake_addrinfo = [(2, 1, 6, "", ("127.0.0.1", 0))]
        with patch("src._http_utils.socket.getaddrinfo", return_value=fake_addrinfo):
            with pytest.raises(TargetValidationError, match="private IP"):
                validate_target("evil-rebind.example.com")

    def test_denylist_blocks_host(self):
        with patch.object(
            __import__("src._http_utils", fromlist=["_DENYLIST_HOSTS"]),
            "_DENYLIST_HOSTS",
            frozenset({"blocked.example.com"}),
        ):
            with pytest.raises(TargetValidationError, match="Denylisted"):
                validate_target("blocked.example.com")

    def test_strips_whitespace(self):
        result = validate_target("  example.com  ")
        assert result == "https://example.com"


class TestNormaliseTarget:
    def test_adds_https(self):
        assert normalise_target("example.com") == "https://example.com"

    def test_preserves_http(self):
        assert normalise_target("http://example.com") == "http://example.com"

    def test_preserves_https(self):
        assert normalise_target("https://example.com") == "https://example.com"

    def test_strips_whitespace(self):
        assert normalise_target("  example.com  ") == "https://example.com"
