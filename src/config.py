"""Centralised configuration with env-var overrides."""

from __future__ import annotations

import os

# HTTP timeouts (seconds)
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "15"))
CRAWL_TIMEOUT = int(os.getenv("CRAWL_TIMEOUT", "20"))
SSL_TIMEOUT = int(os.getenv("SSL_TIMEOUT", "10"))
PATH_SCAN_TIMEOUT = int(os.getenv("PATH_SCAN_TIMEOUT", "10"))
PORT_SCAN_TIMEOUT = int(os.getenv("PORT_SCAN_TIMEOUT", "3"))
PORT_SCAN_CONCURRENCY = int(os.getenv("PORT_SCAN_CONCURRENCY", "20"))
JS_MINE_TIMEOUT = int(os.getenv("JS_MINE_TIMEOUT", "30"))
PASSIVE_TIMEOUT = int(os.getenv("PASSIVE_TIMEOUT", "15"))
BREACH_TIMEOUT = int(os.getenv("BREACH_TIMEOUT", "15"))
DNS_LIFETIME = int(os.getenv("DNS_LIFETIME", "8"))

# Crawler limits
MAX_PAGES = int(os.getenv("MAX_PAGES", "50"))
MAX_SCRIPTS = int(os.getenv("MAX_SCRIPTS", "50"))
PATH_CONCURRENCY = int(os.getenv("PATH_CONCURRENCY", "10"))
BREACH_EMAIL_CAP = int(os.getenv("BREACH_EMAIL_CAP", "10"))
PLAYWRIGHT_EXTRA_WAIT_MS = int(os.getenv("PLAYWRIGHT_EXTRA_WAIT_MS", "500"))
HIBP_RATE_LIMIT_DELAY = float(os.getenv("HIBP_RATE_LIMIT_DELAY", "1.5"))
JS_FETCH_CONCURRENCY = int(os.getenv("JS_FETCH_CONCURRENCY", "5"))
SCAN_CONCURRENCY = int(os.getenv("SCAN_CONCURRENCY", "5"))
MAX_RESPONSE_BYTES = int(os.getenv("MAX_RESPONSE_BYTES", str(10 * 1024 * 1024)))

# C99 API integration
C99_API_KEY = os.getenv("C99_API_KEY", "")
C99_TIMEOUT = int(os.getenv("C99_TIMEOUT", "20"))

# Nuclei integration
NUCLEI_API_URL = os.getenv("NUCLEI_API_URL", "")
NUCLEI_TIMEOUT = int(os.getenv("NUCLEI_TIMEOUT", "300"))

# CVE lookup
CVE_LOOKUP_TIMEOUT = int(os.getenv("CVE_LOOKUP_TIMEOUT", "10"))

# Screenshot settings
SCREENSHOT_TIMEOUT = int(os.getenv("SCREENSHOT_TIMEOUT", "10000"))  # ms
SCREENSHOT_MAX_PER_SCAN = int(os.getenv("SCREENSHOT_MAX_PER_SCAN", "10"))
SCREENSHOT_WIDTH = int(os.getenv("SCREENSHOT_WIDTH", "1280"))
SCREENSHOT_HEIGHT = int(os.getenv("SCREENSHOT_HEIGHT", "720"))

# User-Agent strings
UA_HONEST = os.getenv("UA_HONEST", "GreypingCrawler/1.0")
UA_BROWSER = os.getenv(
    "UA_BROWSER",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
)
