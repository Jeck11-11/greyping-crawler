# GreyPing Nuclei API Scanner

This repository provides a Docker-based scanning system where Nuclei runs in **ephemeral containers** triggered by an API. The API queues scans into Redis and a worker executes them via `docker run --rm projectdiscovery/nuclei`.

## Project structure

```
.
├── api.py                # FastAPI HTTP API
├── worker.py             # Celery worker that runs docker-based scans
├── Dockerfile            # Builds the API/worker image
├── docker-compose.yml    # API + worker + Redis
└── requirements.txt      # Python dependencies
```

## Requirements

- Docker 20.10+
- Docker Compose v2
- Nuclei templates stored on the host at `/opt/nuclei-templates`

## How it works

1. **API** accepts `POST /scan` with JSON describing the target and scan mode.
2. **Redis queue** receives the task.
3. **Worker** pulls the latest Nuclei image, runs `docker run --rm` with the right flags, streams JSON output, and posts each result to Xano.

## API

`POST /scan` expects:

```json
{
  "target": "example.com",
  "mode": "passive|active|full",
  "templates": ["cves", "dns", "http", "cloud"],
  "extra_args": "-severity high,critical"
}
```

### Mode behavior

- **passive** → adds `-passive`
- **active** → default HTTP probes (no extra flags)
- **full** → adds `-scan-all-ips -scan-all-ports`

### Template selection

Template groups map to these paths:

| Group | Template path |
|-------|---------------|
| cves | `/opt/nuclei-templates/cves` |
| dns | `/opt/nuclei-templates/dns` |
| http | `/opt/nuclei-templates/http` |
| cloud | `/opt/nuclei-templates/cloud` |
| network | `/opt/nuclei-templates/network` |

If `templates` is not provided, the worker scans `/opt/nuclei-templates`.

### Command example built by the worker

```bash
docker run --rm \
  -v /opt/nuclei-templates:/templates \
  projectdiscovery/nuclei \
  -u example.com \
  -t /templates/cves,/templates/http \
  -passive \
  -severity high,critical \
  -json
```

## Running the stack

```bash
docker compose up --build
```

The API is exposed on port `8081`.

Make sure the host has templates at `/opt/nuclei-templates` and that Docker is available (the worker uses the host Docker socket to run ephemeral Nuclei containers).

## Curl examples

Passive scan:

```bash
curl -X POST http://VPS:8081/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"dnait.ie","mode":"passive"}'
```

Active CVE scan:

```bash
curl -X POST http://VPS:8081/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"dnait.ie","mode":"active","templates":["cves"]}'
```

Full recon:

```bash
curl -X POST http://VPS:8081/scan \
  -H "Content-Type: application/json" \
  -d '{"target":"dnait.ie","mode":"full","templates":["dns","http","network"]}'
```

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis URL for API and worker. | `redis://redis:6379/0` |
| `RATE_LIMIT_COUNT` | Requests allowed per window per IP. | `5` |
| `RATE_LIMIT_WINDOW` | Rate limit window in seconds. | `60` |
| `NUCLEI_IMAGE` | Docker image for Nuclei. | `projectdiscovery/nuclei` |
| `NUCLEI_TEMPLATES_PATH` | Host path to templates. | `/opt/nuclei-templates` |
| `XANO_URL` | Xano endpoint to POST JSON results. | *(unset)* |
| `XANO_API_KEY` | Optional bearer token for Xano. | *(unset)* |

## Security

- **Domain/IP validation** rejects malformed targets.
- **Shell injection prevention** via argument lists (no `shell=True`).
- **Rate limiting** in API using Redis counters.

## Notes

- The worker always runs `docker pull projectdiscovery/nuclei` before each scan.
- Nuclei is **not** run as a persistent service; each scan is ephemeral.
