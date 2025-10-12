#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> Checking entrypoint shell syntax"
bash -n docker/entrypoint.sh

echo "==> Validating YAML configuration files"
if command -v python3 >/dev/null 2>&1; then
  python3 - "docker-compose.yml" "config/nuclei-config.yaml" <<'PY'
import sys
from pathlib import Path

paths = [Path(p) for p in sys.argv[1:]]
try:
    import yaml
except ModuleNotFoundError:
    print("PyYAML not installed; skipping YAML validation.", file=sys.stderr)
    sys.exit(0)

for path in paths:
    with path.open('r', encoding='utf-8') as handle:
        yaml.safe_load(handle)
    print(f"Validated {path}")
PY
else
  echo "Python3 not available; skipping YAML validation."
fi

echo "==> Attempting docker compose config"
if command -v docker >/dev/null 2>&1; then
  if docker compose version >/dev/null 2>&1; then
    docker compose config >/dev/null
    echo "docker compose config succeeded."
  else
    echo "Docker Compose not available; skipping docker compose config."
  fi
else
  echo "Docker engine not available; skipping docker compose config."
fi
