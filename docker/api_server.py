#!/usr/bin/env python3
import json
import os
import shlex
import subprocess
import uuid
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import List, Optional


DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
TEMPLATE_DIR = Path(os.getenv("TEMPLATE_DIR", DATA_DIR / "templates"))
PROJECT_DIR = Path(os.getenv("PROJECT_DIR", DATA_DIR / "projects"))
LOG_DIR = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))
CONFIG_FILE = os.getenv("NUCLEI_CONFIG", "/etc/nuclei/config.yaml")
DEFAULT_EXTRA_ARGS = os.getenv("NUCLEI_ADDITIONAL_ARGS", "")
SILENT_MODE = os.getenv("NUCLEI_SILENT", "true").lower() == "true"
HOST = os.getenv("NUCLEI_API_HOST", "0.0.0.0")
PORT = int(os.getenv("NUCLEI_API_PORT", "8080"))


def _ensure_dirs() -> None:
    for directory in (DATA_DIR, TEMPLATE_DIR, PROJECT_DIR, LOG_DIR, DATA_DIR / "input"):
        directory.mkdir(parents=True, exist_ok=True)


def _write_targets_file(targets: List[str]) -> Path:
    identifier = uuid.uuid4().hex
    targets_file = DATA_DIR / "input" / f"targets-{identifier}.txt"
    targets_file.write_text("\n".join(targets) + "\n", encoding="utf-8")
    return targets_file


def _build_command(targets_file: Path, extra_args: Optional[str], passive: bool = False) -> tuple[List[str], Path]:
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    label = "passive" if passive else "active"
    output_file = LOG_DIR / f"{label}-api-{timestamp}.txt"
    command = [
        "nuclei",
        *(("-passive",) if passive else ()),
        "-output",
        str(output_file),
        "-jsonl",
        "-config",
        CONFIG_FILE,
        "-list",
        str(targets_file),
    ]
    if SILENT_MODE:
        command.append("-silent")
    if DEFAULT_EXTRA_ARGS:
        command.extend(shlex.split(DEFAULT_EXTRA_ARGS))
    if extra_args:
        command.extend(shlex.split(extra_args))
    return command, output_file


def _parse_findings(text: str) -> list[dict]:
    """Parse nuclei JSONL stdout into structured finding dicts."""
    findings = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        findings.append({
            "template_id": obj.get("template-id", obj.get("templateID", "")),
            "name": info.get("name", ""),
            "severity": info.get("severity", ""),
            "type": obj.get("type", ""),
            "host": obj.get("host", ""),
            "matched_at": obj.get("matched-at", obj.get("matched", "")),
            "url": obj.get("url", ""),
            "matcher_name": obj.get("matcher-name", ""),
            "description": info.get("description", "").strip(),
            "tags": info.get("tags") or [],
            "reference": info.get("reference") or [],
            "extracted_results": obj.get("extracted-results") or [],
            "curl_command": obj.get("curl-command", ""),
            "timestamp": obj.get("timestamp", ""),
        })
    return findings


def _parse_stats(text: str) -> dict:
    """Parse the last stats JSON line from stderr."""
    last_stats = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            last_stats = json.loads(line)
        except json.JSONDecodeError:
            continue
    return last_stats


class NucleiAPIHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: HTTPStatus, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _bad_request(self, message: str) -> None:
        self._send_json(HTTPStatus.BAD_REQUEST, {"error": message})

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path.rstrip("/") != "/scan":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            self._bad_request("Request body required")
            return

        try:
            payload = json.loads(self.rfile.read(content_length))
        except json.JSONDecodeError:
            self._bad_request("Invalid JSON payload")
            return

        targets = payload.get("targets")
        if isinstance(targets, str):
            targets = [targets]
        if not targets or not isinstance(targets, list):
            self._bad_request("Field 'targets' must be a non-empty list or string")
            return

        normalized = [str(target).strip() for target in targets if str(target).strip()]
        if not normalized:
            self._bad_request("Targets must not be empty")
            return

        extra_args = payload.get("additional_args")
        if extra_args is not None and not isinstance(extra_args, str):
            self._bad_request("Field 'additional_args' must be a string when provided")
            return

        passive = payload.get("passive", False)
        timeout_seconds = int(payload.get("timeout", 600))

        _ensure_dirs()
        targets_file = _write_targets_file(normalized)
        command, output_file = _build_command(targets_file, extra_args, passive=passive)

        print(f"[scan] targets={normalized} passive={passive} timeout={timeout_seconds}s", flush=True)
        print(f"[scan] command={' '.join(command)}", flush=True)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            print(f"[scan] timeout after {timeout_seconds}s", flush=True)
            self._send_json(
                HTTPStatus.GATEWAY_TIMEOUT,
                {
                    "error": f"Nuclei scan timed out after {timeout_seconds}s",
                    "command": command,
                    "output_file": str(output_file),
                    "partial_stdout": (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                    "partial_stderr": (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                },
            )
            return
        except Exception as exc:  # noqa: BLE001
            print(f"[scan] failed to execute: {exc}", flush=True)
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Failed to execute nuclei", "detail": str(exc)},
            )
            return

        findings = _parse_findings(completed.stdout or "")
        stats = _parse_stats(completed.stderr or "")

        print(f"[scan] completed exit_code={completed.returncode} findings={len(findings)} templates={stats.get('templates', '?')}", flush=True)

        self._send_json(
            HTTPStatus.OK,
            {
                "target": normalized[0] if len(normalized) == 1 else normalized,
                "findings": findings,
                "stats": {
                    "templates": int(stats.get("templates", 0)),
                    "requests": int(stats.get("requests", "0").split("/")[0]),
                    "total_requests": int(stats.get("total", 0)),
                    "matched": int(stats.get("matched", 0)),
                    "errors": int(stats.get("errors", 0)),
                    "duration": stats.get("duration", ""),
                    "rps": int(stats.get("rps", 0)),
                } if stats else None,
                "exit_code": completed.returncode,
                "output_file": str(output_file),
            },
        )


def main() -> None:
    _ensure_dirs()
    server = ThreadingHTTPServer((HOST, PORT), NucleiAPIHandler)
    print(f"Nuclei API listening on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
