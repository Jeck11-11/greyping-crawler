"""Tests for centralised configuration."""

from src import config


class TestConfigDefaults:
    def test_http_timeout_default(self):
        assert config.HTTP_TIMEOUT == 15

    def test_crawl_timeout_default(self):
        assert config.CRAWL_TIMEOUT == 20

    def test_ssl_timeout_default(self):
        assert config.SSL_TIMEOUT == 10

    def test_path_scan_timeout_default(self):
        assert config.PATH_SCAN_TIMEOUT == 10

    def test_js_mine_timeout_default(self):
        assert config.JS_MINE_TIMEOUT == 30

    def test_passive_timeout_default(self):
        assert config.PASSIVE_TIMEOUT == 15

    def test_breach_timeout_default(self):
        assert config.BREACH_TIMEOUT == 15

    def test_dns_lifetime_default(self):
        assert config.DNS_LIFETIME == 8

    def test_max_pages_default(self):
        assert config.MAX_PAGES == 50

    def test_max_scripts_default(self):
        assert config.MAX_SCRIPTS == 50

    def test_path_concurrency_default(self):
        assert config.PATH_CONCURRENCY == 10

    def test_breach_email_cap_default(self):
        assert config.BREACH_EMAIL_CAP == 10

    def test_playwright_wait_default(self):
        assert config.PLAYWRIGHT_EXTRA_WAIT_MS == 500

    def test_ua_honest_default(self):
        assert config.UA_HONEST == "GreypingCrawler/1.0"

    def test_ua_browser_contains_chrome(self):
        assert "Chrome" in config.UA_BROWSER
