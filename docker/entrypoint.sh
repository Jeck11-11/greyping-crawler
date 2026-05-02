#!/usr/bin/env sh
set -euo pipefail

DATA_DIR="${DATA_DIR:-/data}"
TEMPLATE_DIR="${TEMPLATE_DIR:-${DATA_DIR}/templates}"
PROJECT_DIR="${PROJECT_DIR:-${DATA_DIR}/projects}"
LOG_DIR="${LOG_DIR:-${DATA_DIR}/logs}"
CONFIG_FILE="${NUCLEI_CONFIG:-/etc/nuclei/config.yaml}"
TARGETS_FILE="${NUCLEI_TARGETS_FILE:-}"
EXTRA_ARGS="${NUCLEI_ADDITIONAL_ARGS:-}"
UPDATE_TEMPLATES="${NUCLEI_UPDATE_TEMPLATES:-true}"
SILENT_MODE="${NUCLEI_SILENT:-true}"

mkdir -p "${TEMPLATE_DIR}" "${PROJECT_DIR}" "${LOG_DIR}"

if [ "${UPDATE_TEMPLATES}" = "true" ]; then
  echo "Updating nuclei templates in ${TEMPLATE_DIR}..."
  if ! nuclei -update-templates; then
    echo "Template update failed; continuing with existing templates" >&2
  fi
fi

TIMESTAMP="$(date +"%Y%m%d_%H%M%S")"
OUTPUT_FILE="${LOG_DIR}/passive-${TIMESTAMP}.txt"

if [ "$#" -eq 0 ] || [ "$1" = "scan" ]; then
  if [ "$#" -gt 0 ]; then
    shift
  fi
  set -- nuclei -project -project-path "${PROJECT_DIR}" -output "${OUTPUT_FILE}" -config "${CONFIG_FILE}"

  if [ "${SILENT_MODE}" = "true" ]; then
    set -- "$@" -silent
  fi

  if [ -n "${TARGETS_FILE}" ] && [ -f "${TARGETS_FILE}" ]; then
    set -- "$@" -list "${TARGETS_FILE}"
  fi

  if [ -n "${EXTRA_ARGS}" ]; then
    # shellcheck disable=SC2086
    set -- "$@" ${EXTRA_ARGS}
  fi
fi

if [ "$#" -gt 0 ] && [ "$1" = "api" ]; then
  shift
  exec python3 /usr/local/bin/nuclei_api.py "$@"
fi

if [ "$#" -gt 0 ] && [ "$1" = "osint-api" ]; then
  shift
  OSINT_HOST="${OSINT_API_HOST:-0.0.0.0}"
  OSINT_PORT="${OSINT_API_PORT:-8089}"
  export PYTHONPATH="/usr/local/lib/osint_api:${PYTHONPATH:-}"
  exec python3 -m uvicorn src.app:app --host "${OSINT_HOST}" --port "${OSINT_PORT}" "$@"
fi

exec "$@"
