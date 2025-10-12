# greyping-crawler
# GreyPing Nuclei Passive Scanner

This repository contains a Docker-first setup for running [ProjectDiscovery Nuclei](https://github.com/projectdiscovery/nuclei) in passive mode. It is tuned for a Hetzner Cloud instance with **2 vCPUs**, **8 GB RAM**, and **80 GB local disk**.

## Features

- Opinionated Docker image built on top of the official `projectdiscovery/nuclei` image.
- Automatic template updates stored on the host for reuse between runs.
- Passive mode enabled by default with conservative concurrency suitable for small servers.
- Result logs and project state persisted to the host filesystem.

## Repository structure

```
.
├── Dockerfile                 # Builds the custom nuclei image with passive defaults
├── docker-compose.yml         # Orchestrates the container for long-running scans
├── docker/entrypoint.sh       # Wraps nuclei with sensible defaults for passive scans
├── config/
│   └── nuclei-config.yaml     # Opinionated nuclei configuration (passive focused)
└── data/                      # Persisted templates, projects, logs (ignored by git)
```

## Requirements

- Docker 20.10+
- Docker Compose v2 (or the Compose plugin bundled with modern Docker releases)

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

## License

This project is distributed under the terms of the MIT License. See [LICENSE](LICENSE) for details.
