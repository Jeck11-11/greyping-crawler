"""Centralised configuration with env-var overrides."""

from __future__ import annotations

import os

# HTTP timeouts (seconds)
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "15"))
CRAWL_TIMEOUT = int(os.getenv("CRAWL_TIMEOUT", "30"))
SSL_TIMEOUT = int(os.getenv("SSL_TIMEOUT", "10"))
PATH_SCAN_TIMEOUT = int(os.getenv("PATH_SCAN_TIMEOUT", "10"))
JS_MINE_TIMEOUT = int(os.getenv("JS_MINE_TIMEOUT", "30"))
PASSIVE_TIMEOUT = int(os.getenv("PASSIVE_TIMEOUT", "15"))
BREACH_TIMEOUT = int(os.getenv("BREACH_TIMEOUT", "15"))
DNS_LIFETIME = int(os.getenv("DNS_LIFETIME", "8"))

# Crawler limits
MAX_PAGES = int(os.getenv("MAX_PAGES", "50"))
MAX_SCRIPTS = int(os.getenv("MAX_SCRIPTS", "50"))
PATH_CONCURRENCY = int(os.getenv("PATH_CONCURRENCY", "10"))
BREACH_EMAIL_CAP = int(os.getenv("BREACH_EMAIL_CAP", "10"))
PLAYWRIGHT_EXTRA_WAIT_MS = int(os.getenv("PLAYWRIGHT_EXTRA_WAIT_MS", "2000"))
HIBP_RATE_LIMIT_DELAY = float(os.getenv("HIBP_RATE_LIMIT_DELAY", "1.5"))
JS_FETCH_CONCURRENCY = int(os.getenv("JS_FETCH_CONCURRENCY", "5"))
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "5"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", str(10 * 1024 * 1024)))

# User-Agent strings
UA_HONEST = os.getenv("UA_HONEST", "GreypingCrawler/1.0")
UA_BROWSER = os.getenv(
    "UA_BROWSER",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
)
