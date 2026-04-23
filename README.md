# GreyPing OSINT Reconnaissance API

A comprehensive, production-grade reconnaissance API for automated website security assessment. Combines passive intelligence gathering (DNS, CT logs, WHOIS, Wayback) with active probing (crawling, path scanning, secret detection) and vulnerability correlation to deliver quantified risk scores via the FAIR framework.

> **Authorised security testing only.** This tool is designed for assessing assets you own or have explicit written permission to test. Unauthorised scanning may violate applicable laws and third-party terms of service (HIBP, target websites, etc.).

## Architecture Overview

### What GreyPing Does

The GreyPing API performs rapid, parallel reconnaissance across multiple targets:

1. **Discovers exposed infrastructure** — identifies unpatched software, weak TLS, missing security headers, credential leaks, and exposed administrative panels.
2. **Extracts attack surface** — harvests email addresses, phone numbers, links, API endpoints, JavaScript sourcemaps, and technology stack details from crawled content.
3. **Correlates breach history** — checks targets and extracted emails against Have I Been Pwned and identifies which breaches are most relevant.
4. **Quantifies risk** — applies the FAIR framework (Threat, Vulnerability, Control Strength, Loss Magnitude) to produce actionable risk scores suitable for dashboards and workflow automation.

### Three Scan Modes: Latency vs. Coverage

All three modes orchestrate 8 concurrent workers using `asyncio.gather()` with bounded semaphores to prevent resource exhaustion.

| Mode | What it does | Latency | Traffic to target | Best for |
|------|---|---|---|---|
| **`/scan/passive`** | DNS, CT logs, WHOIS, Wayback snapshots, HIBP breach lookup | ~5–10s | Zero | Stealth-first reconnaissance; initial discovery |
| **`/scan/lighttouch`** | Single HTTP GET to landing page + landing-page-only analysis (no crawl) | ~10–20s | 1 request | WAF evasion; quick sanity checks; light footprint |
| **`/scan`** (full) | Full crawl (BFS to configurable depth) + JS rendering + path probes + all passive intel | ~30–120s | 50–200+ requests | Complete surface mapping; maximum signal |

### Orchestration Model

Each scan mode orchestrates independent workers in parallel:

```
Request → Input Validation → Async Worker Pool (8x concurrent) → Results Aggregation → Post-Processing → Response
                                     ↓
                    ┌─ SSL/TLS Certificate Inspection
                    ├─ Passive DNS Resolution (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR, DNSSEC)
                    ├─ Certificate Transparency Log Search (crt.sh)
                    ├─ RDAP/WHOIS Lookup (registrar, dates, nameservers)
                    ├─ Wayback Machine Snapshots
                    ├─ HTTP Security Headers Audit
                    ├─ Cookie Security Analysis
                    ├─ Have I Been Pwned Breach Correlation
                    ├─ Technology Fingerprinting (60+ signatures)
                    ├─ Web Crawler (optional JS rendering)
                    ├─ Sensitive Path Scanning (57 paths: .git, .env, /admin, /graphql, /.well-known/*)
                    ├─ Contact Extraction (emails, phones, social profiles from crawled pages)
                    ├─ Link Extraction & Classification (internal vs. external)
                    ├─ JavaScript Mining (API endpoints, internal hosts, sourcemaps)
                    ├─ Secret Detection (20+ patterns: AWS, GCP, GitHub, Stripe, Slack, JWTs, private keys, DB URLs, etc.)
                    ├─ Indicator-of-Compromise Scanning (cryptominers, hidden iframes, obfuscated code)
                    ├─ Nuclei Vulnerability Templates (8,000+ templates for CVE, misconfig, exposure)
                    ├─ CVE Correlation from Tech Stack (osv.dev)
                    └─ Favicon Hashing (mmh3 for Shodan/Censys pivoting)
                                     ↓
                    Post-processing applies EASM report summary + FAIR framework signals
                                     ↓
                    JSON response with findings, risk scores, and errors
```

---

## API Endpoints

All endpoints are namespaced under `/recon` (except orchestrated endpoints `/scan*`).

### Orchestrated Scan Endpoints (Batch Processing)

These endpoints accept multiple targets and run all applicable workers for each target in parallel.

| Method | Path | Scan Mode | Purpose |
|--------|------|-----------|---------|
| POST | `/scan/passive` | Passive | DNS, CT, WHOIS, Wayback, HIBP only (zero traffic to target) |
| POST | `/scan/lighttouch` | Lighttouch | Landing page fetch + single-request analysis (WAF-friendly) |
| POST | `/scan` | Full | Complete crawl + JS render + paths + all passive intel |

### Discovery Endpoints (Individual Capabilities)

Fingerprinting, surface mapping, and vulnerability identification.

| Method | Path | Purpose | Scan Mode | Output |
|--------|------|---------|-----------|--------|
| POST | `/recon/paths` | Probe for exposed sensitive paths | Lighttouch+ | List of HTTP status codes per path |
| POST | `/recon/tech` | Identify installed technologies, frameworks, CDNs, WAFs | Lighttouch+ | List of detected tech with categories/versions |
| POST | `/recon/js-intel` | Mine JavaScript bundles for endpoints, internal hosts, sourcemaps | Full | API routes, internal hosts, sourcemap URLs |
| POST | `/recon/nuclei` | **[NEW]** Run 8,000+ Nuclei vulnerability templates | Passive | Vulnerability findings, severity, matched URLs |
| POST | `/recon/favicon` | **[NEW]** Extract and hash favicon for Shodan/Censys pivoting | Lighttouch | mmh3 hash, size, content-type |

### Network & Security Endpoints

TLS, HTTP headers, cookies, and email security.

| Method | Path | Purpose | Scan Mode | Output |
|--------|------|---------|-----------|--------|
| POST | `/recon/ssl` | Grade TLS certificate, check expiry, cipher strength, protocol versions | Lighttouch | Certificate grade, validity, issues, expiry |
| POST | `/recon/headers` | Audit HTTP security headers (HSTS, CSP, X-Frame-Options, etc.) | Lighttouch | Headers present, grades, missing recommendations |
| POST | `/recon/cookies` | Analyze cookie security flags (Secure, HttpOnly, SameSite) | Full | Cookie findings, missing security flags |
| POST | `/recon/email-security` | Parse SPF, DKIM, DMARC records and assign security grades | Passive | SPF policy, DKIM selectors found, DMARC alignment grade |

### Content Endpoints (Crawling & Extraction)

Web crawling, contact harvesting, link mapping, and content analysis.

| Method | Path | Purpose | Scan Mode | Output |
|--------|------|---------|-----------|--------|
| POST | `/recon/crawl` | Crawl target(s) and return raw per-page results | Full | URLs, titles, status codes, content snippets, JS-rendered flag |
| POST | `/recon/contacts` | Extract emails, phone numbers, social profiles from crawled pages | Full | Deduplicated list of contacts found |
| POST | `/recon/links` | Extract and classify internal vs. external links with anchor text | Full | Categorized links, frequency, anchor text |
| POST | `/recon/secrets` | Detect exposed secrets in page bodies, scripts, comments | Full | Secret type, location (HTML comment, script, etc.), redacted preview |
| POST | `/recon/ioc` | Detect indicators of compromise (cryptominers, hidden iframes, obfuscated JS) | Full | IoC findings with severity and description |

### Passive Intelligence Endpoints

Zero-traffic reconnaissance via public databases.

| Method | Path | Purpose | Scan Mode | Output |
|--------|------|---------|-----------|--------|
| POST | `/recon/dns` | Query DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR, DNSSEC) | Passive | Structured DNS records |
| POST | `/recon/ct` | Search Certificate Transparency logs for subdomains | Passive | Certificates, issue dates, subdomains |
| POST | `/recon/whois` | RDAP/WHOIS lookup (registrar, dates, nameservers, admin contacts) | Passive | Registrant info, registrar, dates, nameservers |
| POST | `/recon/wayback` | Internet Archive snapshots with timeline | Passive | Snapshot URLs, dates, available captures |
| POST | `/recon/breaches` | Check domain and optional seed emails against HIBP | Passive | Breach records, dates, compromised data classes, source |

---

## Module Inventory (30+ Components)

### Core Orchestration
| Module | Purpose | 
|--------|---------|
| `app.py` (918 LOC) | FastAPI application, 3 scan orchestrators (`_scan_single_target`, `_lighttouch_single_target`, `_passive_single_target`), endpoint registration, middleware setup |
| `models.py` | All Pydantic v2 request/response schemas; 30+ model classes for findings and results |
| `config.py` | Centralized configuration with environment-variable overrides (concurrency limits, timeouts, API keys, rate limits) |
| `middleware.py` | API key authentication (dev mode support), token-bucket rate limiting per key (separate `/scan` and `/recon` buckets) |
| `postprocess.py` | Recursive `fill_not_found()` for stable API contract; ensures all optional fields are populated |

### HTTP/Network Utilities
| Module | Purpose |
|--------|---------|
| `_http_utils.py` | Target validation, SSRF protection (private-IP resolution, DNS rebind detection, scheme validation), denylist enforcement |
| `crawler.py` | Async breadth-first crawler with optional Playwright JS rendering, redirect tracking, page timeout enforcement |
| `favicon.py` | **[NEW]** Favicon fetching + mmh3 hashing for Shodan/Censys pivoting |

### Security Scanning
| Module | Purpose |
|--------|---------|
| `ssl_checker.py` | TLS certificate inspection, expiry check, self-signed detection, cipher suite analysis, protocol version grading |
| `security_headers.py` | HTTP security headers audit (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc.) with grading |
| `cookie_checker.py` | Cookie flag analysis (Secure, HttpOnly, SameSite) per target |
| `secret_scanner.py` | Regex-based detection of 20+ secret pattern families; deduplication; location tagging |
| `ioc_scanner.py` | Detection of cryptominers, hidden iframes, obfuscated JavaScript, credential harvesting patterns |
| `path_scanner.py` | Concurrent probing of 57 sensitive paths with HTTP status tracking |

### Passive Intelligence (Zero-Traffic OSINT)
| Module | Purpose |
|--------|---------|
| `passive_intel.py` | Unified handler for DNS, CT logs, RDAP, Wayback, email security; orchestrates per-target calls |
| `dns_resolver.py` | Async DNS queries (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA, PTR, DNSSEC) |
| `ct_logs.py` | Certificate Transparency log search via crt.sh; subdomain discovery |
| `rdap_client.py` | RDAP/WHOIS lookups (registrar info, dates, nameservers) |
| `wayback_client.py` | Internet Archive API integration for snapshot timelines |
| `breach_checker.py` | Have I Been Pwned v3 API integration with rate limiting and retry logic |

### Content Analysis & Extraction
| Module | Purpose |
|--------|---------|
| `extractors.py` | Email, phone number, social profile extraction from HTML; link parsing |
| `tech_fingerprint.py` | Technology stack identification (60+ signatures) covering CMS, frameworks, CDNs, WAFs, analytics, hosting |
| `js_miner.py` | JavaScript bundle mining (API endpoints, internal hostnames, sourcemap extraction) |
| `email_security.py` | SPF, DKIM, DMARC record parsing with A–F grading |
| `robots_sitemap.py` | robots.txt and sitemap.xml parsing for attack surface discovery |

### Post-Processing & Risk Quantification
| Module | Purpose |
|--------|---------|
| `easm_report.py` | EASM (External Attack Surface Management) report generation; executive summary of findings |
| `fair_signals.py` | **FAIR framework integration** — maps scanner evidence to four factors (TEF, Vulnerability, Control Strength, Loss Magnitude); computes risk score |
| `_link_utils.py` | Utility functions for link normalization, social URL detection, external URL classification |
| `_social_utils.py` | Social platform detection (Twitter, LinkedIn, Facebook, etc.) from URLs and HTML |

### Integration & New Capabilities
| Module | Purpose |
|--------|---------|
| `nuclei_client.py` | **[NEW]** Async HTTP client for nuclei-api sidecar; JSONL finding parser; vulnerability template integration |
| `cve_lookup.py` | **[NEW]** CVE correlation via osv.dev; matches detected tech versions to known vulnerabilities |

---

## Response Structure & Data Models

All endpoints follow a consistent response pattern:

### Orchestrated Scan Response (`/scan`, `/scan/lighttouch`, `/scan/passive`)

```json
{
  "status": "completed|partial|failed",
  "scanned_at": "2026-04-23T12:34:56.123456Z",
  "duration_seconds": 42.5,
  "results": [
    {
      "target": "example.com",
      "final_url": "https://example.com/",
      "status": "success|failed",
      "error": null,
      "ssl": { /* SSLCertResult */ },
      "security_headers": { /* SecurityHeadersResult */ },
      "cookies": [ /* CookieFinding[] */ ],
      "sensitive_paths": [ /* SensitivePathFinding[] */ ],
      "technologies": [ /* TechFinding[] */ ],
      "dns": { /* DNSResult */ },
      "email_security": { /* EmailSecurityResult */ },
      "ct_logs": { /* CTResult */ },
      "whois": { /* RDAPResult */ },
      "wayback": { /* WaybackResult */ },
      "breaches": [ /* BreachFinding[] */ ],
      "contacts": { /* ContactInfo */ },
      "links": { /* LinkInfo */ },
      "crawl_results": [ /* PageResult[] */ ],
      "secrets": [ /* SecretFinding[] */ ],
      "ioc": [ /* IoCFinding[] */ ],
      "nuclei_findings": [ /* NucleiFinding[] */ ],
      "cve_findings": [ /* CVEFinding[] */ ],
      "favicon": { /* FaviconResult */ },
      "pages_crawled": 5,
      "easm_report": { /* EASMReport */ },
      "fair_signals": { /* FAIRSignals */ }
    }
  ]
}
```

### Individual Recon Endpoint Response Pattern

All `/recon/*` endpoints return a list of per-target results:

```json
[
  {
    "target": "example.com",
    "error": null,
    /* endpoint-specific fields */
  }
]
```

### FAIR Signals (Risk Quantification)

Every `DomainResult` includes a `fair_signals` object:

```json
{
  "risk_score": 67,
  "threat_event_frequency": 55,
  "vulnerability": 72,
  "control_strength": 40,
  "loss_magnitude": 60,
  "signals": [
    {
      "name": "missing_hsts",
      "factor": "control_strength",
      "impact": -15,
      "evidence": "HSTS header not present"
    }
  ]
}
```

See [docs/FAIR.md](docs/FAIR.md) for detailed risk factor documentation.

---

## What's New: Quick-Win Sprint Features

### Nuclei Vulnerability Scanning

The `/recon/nuclei` endpoint integrates with the nuclei-api sidecar to run 8,000+ vulnerability templates. Templates cover CVEs, misconfigurations, exposed services, and known weaknesses.

**Usage:**
```bash
curl -X POST http://localhost:8089/recon/nuclei \
  -H "Content-Type: application/json" \
  -d '{
    "targets": ["example.com"],
    "severity": "medium,high,critical"
  }'
```

**Output:** List of NucleiFindings with template ID, severity, matched URL, and extracted results.

### CVE Correlation from Technology Stack

The codebase automatically matches detected technologies (from `tech_fingerprint`) against known vulnerabilities via osv.dev. When `/scan` or `/recon/tech` runs, CVE data is automatically appended.

**Example:** If jQuery 3.3.1 is detected, the system queries osv.dev and surfaces related CVEs (e.g., CVE-2020-11022 XSS in htmlPrefilter).

**Output:** List of CVEFindings with CVSS score, severity, affected tech, and advisory links.

### Favicon Hashing (Shodan/Censys Pivoting)

The `/recon/favicon` endpoint extracts the target's favicon and computes its mmh3 hash for pivoting on threat intelligence platforms.

**Usage:**
```bash
curl -X POST http://localhost:8089/recon/favicon \
  -H "Content-Type: application/json" \
  -d '{"targets": ["example.com"]}'
```

**Output:** mmh3 hash, favicon size, content-type. Use hash to search Shodan/Censys for other assets with the same icon.

---

## Request Payloads

### Common Request Schema (most `/recon/*` endpoints)

```json
{
  "targets": ["example.com", "acme.test", "https://api.example.net"],
  "timeout": 20
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `targets` | `list[str]` | required | One or more domains/URLs. Bare hostnames are auto-prefixed with `https://`. |
| `timeout` | `int` | 20 | Per-request timeout in seconds. |

### Crawl-Based Endpoints (`/recon/crawl`, `/recon/contacts`, `/recon/links`, `/recon/secrets`, `/recon/ioc`)

```json
{
  "targets": ["example.com"],
  "render_js": false,
  "follow_redirects": true,
  "max_depth": 1,
  "timeout": 30
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `targets` | `list[str]` | required | Domains/URLs to crawl. |
| `render_js` | `bool` | false | Use headless Chromium for JavaScript-heavy sites. (Not available in Docker; falls back to static HTML.) |
| `follow_redirects` | `bool` | true | Follow HTTP 3xx chains. |
| `max_depth` | `int` | 1 | BFS crawl depth (0 = landing page only). |
| `timeout` | `int` | 30 | Per-request timeout in seconds. |

### Breach Check Endpoint (`/recon/breaches`)

```json
{
  "targets": ["example.com"],
  "emails": ["alice@example.com", "bob@example.com"],
  "timeout": 20
}
```

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `targets` | `list[str]` | required | Domains to check. |
| `emails` | `list[str]` | [] | Optional seed emails to check in addition to harvested emails. |
| `timeout` | `int` | 20 | Per-request timeout in seconds. |

---

## Configuration

### Environment Variables

Create a `.env` file (see `.env.example` for the full list):

| Variable | Default | Purpose |
|----------|---------|---------|
| `OSINT_API_KEYS` | _(unset = dev mode)_ | Comma-separated API keys. When unset, auth is disabled. |
| `HIBP_API_KEY` | _(unset)_ | Have I Been Pwned v3 API key. |
| `NUCLEI_API_URL` | _(unset)_ | nuclei-api sidecar URL (e.g., `http://nuclei-api:8080`). If unset, `/recon/nuclei` returns error. |
| `RATE_LIMIT_SCAN` | 60 | Requests per minute for `/scan*` endpoints (per key/IP). 0 = disabled. |
| `RATE_LIMIT_RECON` | 300 | Requests per minute for `/recon/*` endpoints (per key/IP). 0 = disabled. |
| `HTTP_TIMEOUT` | 15 | Landing page fetch timeout (seconds). |
| `CRAWL_TIMEOUT` | 30 | Crawler per-page timeout (seconds). |
| `MAX_PAGES` | 50 | Max pages crawled per domain. |
| `PATH_CONCURRENCY` | 10 | Concurrent path scanner workers. |
| `LOG_LEVEL` | INFO | Python logging level. |

---

## Authentication & Rate Limiting

### API Key Authentication

Set `OSINT_API_KEYS=key1,key2,key3` to enable. Pass the header:
```bash
curl -H "X-API-Key: key1" http://localhost:8089/scan/passive -d ...
```

When `OSINT_API_KEYS` is unset, auth is disabled (dev mode).

### Rate Limiting

Token-bucket rate limiting is applied per API key (or IP if anonymous). Separate limits for `/scan*` and `/recon*`:

- **`RATE_LIMIT_SCAN`**: requests per minute for `/scan`, `/scan/lighttouch`, `/scan/passive`
- **`RATE_LIMIT_RECON`**: requests per minute for `/recon/*`

Set to 0 to disable rate limiting.

---

## Running Locally

### Prerequisites

- Python 3.11+
- `pip`

### Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
playwright install chromium  # one-time download for JS rendering
```

### Run the API

```bash
uvicorn src.app:app --reload --host 127.0.0.1 --port 8089
```

### Run Tests

```bash
pytest -v
```

All 377 tests should pass. Tests use mocked HTTP/Playwright responses; no outbound network access required.

---

## Running in Docker

### Prerequisites

- Docker Engine 20.10+
- Docker Compose v2

### Setup

```bash
cp .env.example .env
# edit .env with your API keys (HIBP_API_KEY, OSINT_API_KEYS, NUCLEI_API_URL)
docker compose build
docker compose up -d osint-api
curl http://localhost:8089/health  # verify API is running
```

### JavaScript Rendering Note

The Docker image is built on Alpine Linux (musl libc). Playwright does not publish Alpine-compatible wheels, so **JavaScript rendering (`render_js`) is not available in Docker**. The crawler falls back to static httpx fetching automatically. If you need JS rendering, run the API locally (see "Running Locally" above).

---

## Risk Quantification: FAIR Framework

Every scan result includes a `fair_signals` object that quantifies risk using the FAIR (Factor Analysis of Information Risk) framework. FAIR combines four factors to compute an overall risk score (0–100):

1. **Threat Event Frequency (TEF)** — How likely are threat actors to target this asset? (Raised by: exposed CMS, webmail, secrets, suspicious IoCs)
2. **Vulnerability (V)** — How likely is a threat to succeed? (Raised by: missing headers, expired SSL, weak TLS, unpatched CVEs)
3. **Control Strength (CS)** — How effective are defensive measures? (Raised by: HSTS, CSP, WAF, strong email security)
4. **Loss Magnitude (LM)** — How much harm if exploited? (Raised by: credential harvesting, secrets, breaches, sensitive tech)

```
Risk = Loss Event Frequency × Loss Magnitude
Loss Event Frequency = TEF × Vulnerability / (1 + Control Strength attenuator)
```

For detailed documentation on risk factors, evidence mapping, and interpretation, see [docs/FAIR.md](docs/FAIR.md).

---

## Security & Responsible Use

- **Authorised testing only.** Crawling and reconnoitering third-party domains without permission may violate applicable laws and upstream services' acceptable-use policies.
- **Rate limiting.** Configure `RATE_LIMIT_SCAN` and `RATE_LIMIT_RECON` appropriately to avoid overwhelming target infrastructure or triggering WAF/IP blocks.
- **API key rotation.** Regularly rotate `OSINT_API_KEYS` and upstream API credentials (HIBP_API_KEY, etc.).
- **Log monitoring.** Review logs regularly (`docker compose logs osint-api`) for errors or unexpected behaviour.
- **Update frequently.** Run `docker compose build --pull` periodically to incorporate security patches.

---

## Troubleshooting

### `/recon/nuclei` returns "NUCLEI_API_URL not configured"

Set the `NUCLEI_API_URL` environment variable to the nuclei-api sidecar URL (e.g., `http://nuclei-api:8080`).

### JavaScript rendering not working in Docker

Playwright does not support Alpine Linux. The crawler automatically falls back to static HTML. To use JS rendering, run the API locally (see "Running Locally" above).

### High memory usage

Adjust the concurrency limits in `.env`:
- `SCAN_CONCURRENCY` — max concurrent targets per scan
- `PATH_CONCURRENCY` — max concurrent path probes
- `JS_FETCH_CONCURRENCY` — max concurrent JS bundle downloads

### Crawl timeout exceeded

Increase `CRAWL_TIMEOUT` in `.env`. Default is 30 seconds per page.

---

## License

This project is distributed under the terms of the MIT License. See [LICENSE](LICENSE) for details.

---

## Support

For questions, issues, or feature requests, open an issue on GitHub or contact the maintainer.
