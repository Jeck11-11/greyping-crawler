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


def _build_command(targets_file: Path, extra_args: Optional[str]) -> tuple[List[str], Path]:
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    output_file = LOG_DIR / f"passive-api-{timestamp}.txt"
    command = [
        "nuclei",
        "-passive",
        "-project",
        "-project-path",
        str(PROJECT_DIR),
        "-output",
        str(output_file),
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

        _ensure_dirs()
        targets_file = _write_targets_file(normalized)
        command, output_file = _build_command(targets_file, extra_args)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as exc:  # noqa: BLE001
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "Failed to execute nuclei", "detail": str(exc)},
            )
            return

        self._send_json(
            HTTPStatus.OK,
            {
                "command": command,
                "targets_file": str(targets_file),
                "output_file": str(output_file),
                "exit_code": completed.returncode,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
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
