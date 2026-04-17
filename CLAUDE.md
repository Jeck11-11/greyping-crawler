# GreyPing OSINT Reconnaissance API

FastAPI + Pydantic v2 API for automated website reconnaissance. Crawls domains
to extract contacts, secrets, technologies, security posture, and breach data.

## Architecture

**3 scan modes** (orchestrated endpoints):
- `/scan` — full crawl + JS render + breach check + path probes
- `/scan/lighttouch` — single GET per target, WAF-friendly
- `/scan/passive` — zero traffic to target (DNS, CT logs, RDAP, Wayback, HIBP)

**16 recon endpoints** (`/recon/*`) — individual capabilities:
SSL, headers, cookies, crawl, contacts, links, secrets, IoC, paths, tech,
js-intel, breaches, dns, ct, whois, wayback.

## Key Modules

| Module | Purpose |
|---|---|
| `src/app.py` | FastAPI app, scan orchestrators, endpoint registration |
| `src/routers/` | Per-capability recon endpoints (5 router files) |
| `src/crawler.py` | Async crawler with optional Playwright JS rendering |
| `src/passive_intel.py` | DNS, CT, RDAP, Wayback, email security, IP/ASN enrichment |
| `src/easm_report.py` | EASM report builder (post-processing layer) |
| `src/models.py` | All Pydantic v2 models |
| `src/config.py` | Centralised settings with env-var overrides |
| `src/middleware.py` | API key auth + rate limiting middleware |
| `src/_http_utils.py` | HTTP helpers, target validation, SSRF protection |
| `src/postprocess.py` | Recursive "not_found" filler for empty fields |

## Running Locally

```bash
pip install -r requirements.txt
uvicorn src.app:app --host 0.0.0.0 --port 8089
```

Playwright (optional, for JS rendering):
```bash
pip install -r requirements-dev.txt
playwright install chromium
```

## Running in Docker

```bash
cp .env.example .env   # edit with your keys
docker compose up osint-api
```

Playwright is unavailable in Docker (Alpine/musl) — the crawler falls back
to static httpx fetching automatically.

## Testing

```bash
pip install -r requirements-dev.txt
pytest -v
```

208 tests covering all modules and endpoints.

## Environment Variables

See `.env.example` for the full list. Key variables:

| Variable | Default | Description |
|---|---|---|
| `OSINT_API_KEYS` | _(empty = auth disabled)_ | Comma-separated API keys |
| `HIBP_API_KEY` | _(empty)_ | Have I Been Pwned API key |
| `RATE_LIMIT_SCAN` | `60` | Scan endpoint rate limit (req/min, 0=off) |
| `RATE_LIMIT_RECON` | `300` | Recon endpoint rate limit (req/min, 0=off) |
| `HTTP_TIMEOUT` | `15` | Landing page fetch timeout (seconds) |
| `CRAWL_TIMEOUT` | `30` | Crawler per-page timeout (seconds) |
| `MAX_PAGES` | `50` | Max pages per domain crawl |
| `TARGET_DENYLIST` | _(empty)_ | Comma-separated blocked hostnames |
| `LOG_LEVEL` | `INFO` | Logging level |

## Auth

Set `OSINT_API_KEYS=key1,key2` to enable. Pass `X-API-Key: key1` header.
When unset, auth is disabled (dev mode).

## Deployment

VPS: Docker image based on `projectdiscovery/nuclei:latest` (Alpine).
Exposes port 8089 for the OSINT API and 8080 for the nuclei API.
