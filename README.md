# greyping-crawler
# GreyPing Nuclei Passive Scanner & OSINT Reconnaissance API

This repository contains a Docker-first setup bundling two complementary services for authorised security assessments:

1. **Nuclei Passive Scanner** – a hardened wrapper around [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) running in passive mode, tuned for a Hetzner Cloud instance with **2 vCPUs**, **8 GB RAM**, and **80 GB local disk**.
2. **OSINT Reconnaissance API** – an asynchronous FastAPI service that crawls web targets, extracts contacts / links / metadata, detects exposed secrets in page bodies, and correlates domains and emails against the Have I Been Pwned breach database.

Both services are packaged in the same image and can be run individually or side-by-side via `docker compose`.

## Features

### Nuclei passive scanner
- Opinionated Docker image built on top of the official `projectdiscovery/nuclei` image.
- Automatic template updates stored on the host for reuse between runs.
- Passive mode enabled by default with conservative concurrency suitable for small servers.
- Result logs and project state persisted to the host filesystem.

### OSINT reconnaissance API
- Batch scanning of multiple domains in a single request (`asyncio.gather` fan-out).
- Static fetching via `httpx` **or** full JavaScript rendering via headless Chromium (Playwright).
- Breadth-first crawl with configurable depth and per-domain page caps.
- Contact extraction: emails, phone numbers, and social-profile links across 12+ platforms.
- Internal / external link classification with anchor-text capture.
- Secret scanning across 20+ pattern families (AWS, GCP, GitHub, Stripe, Slack, JWTs, private keys, DB URLs, etc.) with value redaction and deduplication.
- Breach lookups against the Have I Been Pwned v3 API for both the domain and up to ten harvested emails.
- Structured JSON responses suitable for direct ingestion by a security dashboard.

## Repository structure

```
.
├── Dockerfile                 # Builds the custom nuclei + OSINT API image
├── docker-compose.yml         # Orchestrates nuclei, nuclei-api, and osint-api
├── docker/entrypoint.sh       # Dispatches to nuclei scan / nuclei api / osint-api
├── config/
│   └── nuclei-config.yaml     # Opinionated nuclei configuration (passive focused)
├── src/                       # OSINT reconnaissance API (FastAPI + Playwright)
│   ├── app.py                 # FastAPI entrypoint and request orchestration
│   ├── models.py              # Pydantic request/response schemas
│   ├── crawler.py             # Async static + JS-rendered crawler
│   ├── extractors.py          # Contact, link, and metadata extraction
│   ├── secret_scanner.py      # Regex-based secret detection engine
│   └── breach_checker.py      # Have I Been Pwned integration
├── tests/                     # pytest suite for the OSINT API
├── pyproject.toml             # pytest / asyncio configuration
├── requirements.txt           # Runtime Python dependencies (Docker)
├── requirements-dev.txt       # Adds Playwright + pytest for local development
└── data/                      # Persisted templates, projects, logs (ignored by git)
```

## Requirements

- Docker 20.10+
- Docker Compose v2 (or the Compose plugin bundled with modern Docker releases)
- *(Local development only)* Python 3.11+ and a one-time `playwright install chromium` for the OSINT API test suite

## Quick start

1. **Clone this repository on the Hetzner server**

   ```bash
   git clone https://github.com/your-org/greyping-crawler.git
   cd greyping-crawler
   ```

2. **Place your targets** in `data/input/targets.txt`. The file should contain one host per line.

   ```bash
   mkdir -p data/input
   echo "example.com" >> data/input/targets.txt
   ```

3. **Build and start the container**

   ```bash
   docker compose build
   docker compose up -d
   ```

4. **View the logs** to watch the passive scan progress.

   ```bash
  docker compose logs -f
  ```

5. **Inspect results** under `data/logs/`. Each run produces a timestamped `passive-<timestamp>.txt` file as well as a JSONL record if enabled in the config.

## Setting up a testing environment

If you want to validate the container locally before deploying it to the Hetzner server, the following workflow mirrors the production setup:

1. **Install prerequisites**

   Ensure Docker Engine (20.10 or newer) and Docker Compose v2 are available. On macOS or Windows, Docker Desktop already bundles both components. On Linux you can follow [Docker's official installation guide](https://docs.docker.com/engine/install/) and then install the Compose plugin via your package manager or the provided convenience script.

2. **Prepare a working directory**

   ```bash
   git clone https://github.com/your-org/greyping-crawler.git
   cd greyping-crawler
   mkdir -p data/input
   echo "example.com" > data/input/targets.txt
   ```

   The repository expects a writable `data/` directory where templates, projects, and logs will persist between container runs. Populating `targets.txt` with a sample host allows you to exercise the passive scan flow end-to-end.

3. **Run the lightweight repo checks**

   ```bash
   ./scripts/test.sh
   ```

   The helper script verifies the entrypoint shell syntax, validates YAML files when PyYAML is installed, and attempts to run `docker compose config` when Docker is available. Skipped checks are reported explicitly so you know which prerequisites are missing.

4. **Build and smoke-test the image**

   ```bash
   docker compose build
   docker compose run --rm nuclei nuclei -version
   docker compose config
   ```

   The `nuclei -version` command confirms the binary is accessible in the image, while `docker compose config` validates the compose file resolves correctly with your environment variables.

5. **Execute a dry-run passive scan**

   ```bash
   docker compose run --rm \
     -e NUCLEI_SILENT=false \
     nuclei scan
   ```

   Running the `scan` wrapper in the foreground prints nuclei's progress to your terminal. You can check `./data/logs/` afterwards to confirm results were written.

6. **Clean up**

   ```bash
   docker compose down
   rm -rf data
   ```

   Remove the temporary data directory once you finish testing to reclaim disk space.

## Configuration

### Environment variables

The container respects the following variables (set them in `docker-compose.yml` or `.env`):

| Variable | Description | Default |
|----------|-------------|---------|
| `DATA_DIR` | Root directory used to persist nuclei data inside the container. | `/data` |
| `TEMPLATE_DIR` | Directory where nuclei templates are stored. | `/data/templates` |
| `PROJECT_DIR` | Directory for nuclei project state. | `/data/projects` |
| `LOG_DIR` | Directory used for log/scan output. | `/data/logs` |
| `NUCLEI_CONFIG` | Path to the nuclei configuration file. | `/etc/nuclei/config.yaml` |
| `NUCLEI_TARGETS_FILE` | File containing newline-delimited targets. When unset, nuclei expects targets via STDIN or other flags. | *(unset)* |
| `NUCLEI_ADDITIONAL_ARGS` | Additional CLI arguments appended to the generated nuclei command. | *(unset)* |
| `NUCLEI_UPDATE_TEMPLATES` | Set to `false` to skip template updates on start. | `true` |
| `NUCLEI_SILENT` | Toggle nuclei `-silent` flag. Set to `false` for verbose output. | `true` |

### `config/nuclei-config.yaml`

The bundled config file enables passive mode, limits concurrency, and scopes templates to passive-friendly categories. Adjust the values to match your scanning policy.

If you need to customize resolvers or template paths, extend this file and mount it into the container (already done by default in `docker-compose.yml`).

## Operations

- **Updating templates manually**

  ```bash
  docker compose run --rm nuclei nuclei -update-templates -update-directory /data/templates
  ```

- **Running an on-demand scan** with custom arguments:

  ```bash
  docker compose run --rm \
    -e NUCLEI_TARGETS_FILE=/data/input/special.txt \
    -e NUCLEI_ADDITIONAL_ARGS="-stats -tags log4j" \
    nuclei scan
  ```

- **Stopping the service**

  ```bash
  docker compose down
  ```

## API mode

If you want to expose nuclei as a lightweight HTTP API (for passive scans only), use the `nuclei-api` service.

1. **Start the API container**

   ```bash
   docker compose up -d nuclei-api
   ```

2. **Submit a passive scan**

   ```bash
   curl -X POST http://localhost:8080/scan \
     -H "Content-Type: application/json" \
     -d '{"targets":["example.com"],"additional_args":"-stats"}'
   ```

   The response includes the generated targets file, output log location, and nuclei stdout/stderr.

3. **Check API health**

   ```bash
   curl http://localhost:8080/health
   ```

### API configuration

The API uses the same environment variables as the CLI flow plus the following:

| Variable | Description | Default |
|----------|-------------|---------|
| `NUCLEI_API_HOST` | Host address bound by the HTTP server. | `0.0.0.0` |
| `NUCLEI_API_PORT` | Port exposed by the HTTP server. | `8080` |

## OSINT Reconnaissance API

The `osint-api` service exposes an asynchronous FastAPI application that performs real-time website reconnaissance against one or more authorised targets and returns structured JSON suitable for a security dashboard.

### JS rendering note

The Docker image is built on Alpine Linux (musl libc). Playwright does not publish Alpine-compatible wheels, so **JavaScript rendering (`render_js`) is not available when running inside the container**. The crawler falls back to static fetching via `httpx` automatically. If you need JS rendering, run the API locally with `requirements-dev.txt` (see [Local development](#local-development-python) below).

### Starting the service

```bash
docker compose up -d osint-api
# the API binds to 0.0.0.0:8089 inside the container
curl http://localhost:8089/health
```

### Endpoints

| Method | Path            | Purpose                                                                                 |
|--------|-----------------|-----------------------------------------------------------------------------------------|
| GET    | `/health`       | Liveness probe; returns `{"status": "ok"}`.                                             |
| POST   | `/scan`         | Full crawl + extract + secret scan + (optional) breach lookup for one or more targets. |
| POST   | `/scan/quick`   | Single-page shallow scan with `max_depth=0`, `render_js=false` for fast sanity checks.  |

### Request payload

```json
{
  "targets": ["example.com", "https://acme.test"],
  "max_depth": 1,
  "max_pages_per_domain": 15,
  "render_js": true,
  "follow_redirects": true,
  "check_breaches": true,
  "timeout": 20,
  "user_agent": "GreyPingOSINT/1.0"
}
```

| Field                  | Type          | Default            | Notes |
|------------------------|---------------|--------------------|-------|
| `targets`              | `list[str]`   | *(required)*       | One or more domains / URLs. Bare hostnames are auto-prefixed with `https://`. |
| `max_depth`            | `int` `0..5`  | `1`                | BFS crawl depth. `0` = landing page only. |
| `max_pages_per_domain` | `int` `1..50` | `10`               | Hard cap on pages crawled per target. |
| `render_js`            | `bool`        | `false`            | Use headless Chromium for JS-heavy sites. |
| `follow_redirects`     | `bool`        | `true`             | Follow HTTP 3xx chains. |
| `check_breaches`       | `bool`        | `false`            | Query Have I Been Pwned (requires `HIBP_API_KEY`). |
| `timeout`              | `int`         | `20`               | Per-request timeout in seconds. |
| `user_agent`           | `str \| null` | *(library default)*| Custom UA for static and rendered fetches. |

### Example: simple batch scan

```console
$ curl -sS -X POST http://localhost:8089/scan \
    -H "Content-Type: application/json" \
    -d '{
      "targets": ["example.com", "acme.test"],
      "max_depth": 1,
      "render_js": false,
      "check_breaches": false
    }' | jq
```

**Sample response**

```json
{
  "status": "completed",
  "scanned_at": "2026-04-11T09:14:22.481273Z",
  "duration_seconds": 6.42,
  "results": [
    {
      "target": "example.com",
      "final_url": "https://example.com/",
      "status": "success",
      "error": null,
      "pages_crawled": 1,
      "contacts": {
        "emails": ["press@example.com"],
        "phones": ["+1-202-555-0143"],
        "social_profiles": [
          "https://twitter.com/example",
          "https://www.linkedin.com/company/example"
        ]
      },
      "links": {
        "internal": [
          {"url": "https://example.com/about", "text": "About"},
          {"url": "https://example.com/contact", "text": "Contact"}
        ],
        "external": [
          {"url": "https://cdn.example.net/assets/app.js", "text": ""}
        ]
      },
      "pages": [
        {
          "url": "https://example.com/",
          "status_code": 200,
          "title": "Example Domain",
          "description": "Illustrative landing page.",
          "content_snippet": "This domain is for use in illustrative examples in documents...",
          "rendered": false
        }
      ],
      "secrets": [],
      "breaches": []
    },
    {
      "target": "acme.test",
      "final_url": null,
      "status": "failed",
      "error": "connect timeout after 20s",
      "pages_crawled": 0,
      "contacts": {"emails": [], "phones": [], "social_profiles": []},
      "links": {"internal": [], "external": []},
      "pages": [],
      "secrets": [],
      "breaches": []
    }
  ]
}
```

> When at least one target succeeds and another fails, the top-level `status` becomes `"partial"`. A request where every target fails returns `"failed"`.

### Example: quick single-page scan

```console
$ curl -sS -X POST http://localhost:8089/scan/quick \
    -H "Content-Type: application/json" \
    -d '{"targets":["example.com"]}' | jq '.results[0].pages[0]'
```

```json
{
  "url": "https://example.com/",
  "status_code": 200,
  "title": "Example Domain",
  "description": "Illustrative landing page.",
  "content_snippet": "This domain is for use in illustrative examples...",
  "rendered": false
}
```

### Example: detected secrets & breaches

```console
$ curl -sS -X POST http://localhost:8089/scan \
    -H "Content-Type: application/json" \
    -d '{
      "targets": ["staging.example.com"],
      "max_depth": 2,
      "render_js": true,
      "check_breaches": true
    }' | jq '.results[0] | {secrets, breaches}'
```

```json
{
  "secrets": [
    {
      "secret_type": "aws_access_key",
      "value_preview": "AKIA...MPLE",
      "location": "script",
      "source_url": "https://staging.example.com/assets/config.js"
    },
    {
      "secret_type": "jwt_token",
      "value_preview": "eyJh...R8U",
      "location": "html_comment",
      "source_url": "https://staging.example.com/"
    },
    {
      "secret_type": "database_credential",
      "value_preview": "post...ydb",
      "location": "html_comment",
      "source_url": "https://staging.example.com/debug"
    }
  ],
  "breaches": [
    {
      "name": "Adobe",
      "domain": "adobe.com",
      "breach_date": "2013-10-04",
      "pwn_count": 152445165,
      "description": "In October 2013, 153 million Adobe accounts were breached...",
      "data_classes": ["Email addresses", "Password hints", "Passwords", "Usernames"],
      "source": "domain:staging.example.com"
    }
  ]
}
```

All detected secrets are **redacted** — `value_preview` only ever contains the first and last few characters of the match joined by `...`, and duplicates within a page are collapsed so a dashboard never re-counts the same finding.

### Secret detection coverage

| Category      | Pattern families                                                                                         |
|---------------|----------------------------------------------------------------------------------------------------------|
| Cloud         | `aws_access_key`, `aws_secret_key`, `google_api_key`, `google_oauth_token`, `azure_storage_key`, `firebase_url` |
| Dev platforms | `github_token`, `slack_token`, `slack_webhook`, `heroku_api_key`                                         |
| Payments      | `stripe_key`, `stripe_publishable_key`                                                                   |
| Messaging     | `twilio_api_key`, `mailgun_api_key`, `sendgrid_api_key`                                                  |
| Auth / crypto | `jwt_token`, `bearer_token`, `private_key` (RSA/EC/OpenSSH/PGP)                                          |
| Data stores   | `database_credential` (postgres/mysql/mongodb/redis URLs)                                                |
| Generic       | `generic_password` (e.g. `password = "…"` assignments)                                                   |

Each finding is additionally tagged with a coarse location hint — `script`, `html_comment`, `meta`, `style`, or `body` — to help triage severity.

### Breach checking

When `check_breaches=true` and a `HIBP_API_KEY` environment variable is supplied, the API calls:

- `GET https://haveibeenpwned.com/api/v3/breaches?domain=<target>` — all breaches known to involve the domain.
- `GET https://haveibeenpwned.com/api/v3/breachedaccount/<email>?truncateResponse=false` — for up to the first 10 unique emails harvested from the target, rate-limited by the HIBP API contract.

Breach records are deduplicated across the domain and email lookups, and each record is annotated with a `source` field (`domain:<target>` or `email:<addr>`) so the dashboard can explain *why* a result showed up.

If `HIBP_API_KEY` is unset, the breach stage is skipped silently and an empty `breaches` array is returned — the rest of the scan still completes normally.

### OSINT API environment variables

| Variable           | Description                                                             | Default   |
|--------------------|-------------------------------------------------------------------------|-----------|
| `OSINT_API_HOST`   | Bind address for the FastAPI / uvicorn server.                          | `0.0.0.0` |
| `OSINT_API_PORT`   | TCP port exposed by the FastAPI / uvicorn server.                       | `8089`    |
| `HIBP_API_KEY`     | Have I Been Pwned v3 API key (required for `check_breaches=true`).      | *(unset)* |
| `LOG_LEVEL`        | Python logging level for the API process.                               | `INFO`    |

### Local development (Python)

You can run the OSINT API and its test suite directly against a local Python interpreter, which is useful when iterating on extractors or secret patterns without rebuilding the Docker image.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
playwright install chromium   # one-time download for the JS renderer

# Run the API (with full Playwright support)
uvicorn src.app:app --reload --host 127.0.0.1 --port 8089

# Or run the test suite
pytest -q
```

The dev requirements file pulls in the base `requirements.txt` automatically.
The test suite uses mocked HTTP + Playwright responses, so no outbound network access is required.

## Resource considerations

The provided defaults were chosen for the target Hetzner instance:

- `bulk-size: 25` and `rate-limit: 150` keep CPU usage balanced on 2 vCPUs.
- Passive mode emits fewer requests, reducing bandwidth usage.
- Persisting data under `./data` ensures the 80 GB disk is used efficiently for templates and scan history.

Monitor `docker stats` and adjust rate limits as needed if multiple scans will run concurrently.

## Security

- Keep the host firewall locked down; only expose required services.
- Review scan output regularly and rotate logs stored in `data/logs/`.
- Update the image periodically by rebuilding (`docker compose build --pull`).

## Responsible use

Both the Nuclei passive scanner and the OSINT reconnaissance API are intended for use against assets you own or for which you have explicit written authorisation to test. Crawling and breach-correlating third-party domains without permission may violate applicable laws and the acceptable-use policies of upstream services (HIBP, target websites, etc.). You are responsible for ensuring that each target listed in a `/scan` request is in scope for your engagement.

## License

This project is distributed under the terms of the MIT License. See [LICENSE](LICENSE) for details.
