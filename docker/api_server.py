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


def _parse_jsonl(text: str) -> list[dict]:
    """Parse generic JSONL output into a list of dicts."""
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


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

    def _parse_request(self) -> Optional[dict]:
        """Parse and validate common JSON request fields.

        Returns a dict with keys: targets, extra_args, timeout, payload.
        Returns None if the request was invalid (error response already sent).
        """
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            self._bad_request("Request body required")
            return None

        try:
            payload = json.loads(self.rfile.read(content_length))
        except json.JSONDecodeError:
            self._bad_request("Invalid JSON payload")
            return None

        targets = payload.get("targets")
        if isinstance(targets, str):
            targets = [targets]
        if not targets or not isinstance(targets, list):
            self._bad_request("Field 'targets' must be a non-empty list or string")
            return None

        normalized = [str(target).strip() for target in targets if str(target).strip()]
        if not normalized:
            self._bad_request("Targets must not be empty")
            return None

        extra_args = payload.get("additional_args")
        if extra_args is not None and not isinstance(extra_args, str):
            self._bad_request("Field 'additional_args' must be a string when provided")
            return None

        timeout_seconds = int(payload.get("timeout", 600))

        return {
            "targets": normalized,
            "extra_args": extra_args,
            "timeout": timeout_seconds,
            "payload": payload,
        }

    def _run_tool(self, tool_name: str, command: list[str], timeout: int) -> Optional[subprocess.CompletedProcess]:
        """Run a subprocess and handle timeout / execution errors.

        Returns the CompletedProcess on success, or None if an error response
        was already sent.
        """
        print(f"[{tool_name}] command={' '.join(command)}", flush=True)

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            print(f"[{tool_name}] timeout after {timeout}s", flush=True)
            self._send_json(
                HTTPStatus.GATEWAY_TIMEOUT,
                {
                    "error": f"{tool_name} timed out after {timeout}s",
                    "command": command,
                    "partial_stdout": (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or ""),
                    "partial_stderr": (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or ""),
                },
            )
            return None
        except Exception as exc:  # noqa: BLE001
            print(f"[{tool_name}] failed to execute: {exc}", flush=True)
            self._send_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": f"Failed to execute {tool_name}", "detail": str(exc)},
            )
            return None

        return completed

    # ------------------------------------------------------------------
    # GET
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        if self.path.rstrip("/") == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    # ------------------------------------------------------------------
    # POST dispatcher
    # ------------------------------------------------------------------

    def do_POST(self) -> None:
        path = self.path.rstrip("/")
        if path == "/scan":
            self._handle_nuclei_scan()
        elif path == "/probe":
            self._handle_probe()
        elif path == "/crawl":
            self._handle_crawl()
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    # ------------------------------------------------------------------
    # /scan — nuclei (existing behaviour)
    # ------------------------------------------------------------------

    def _handle_nuclei_scan(self) -> None:
        parsed = self._parse_request()
        if parsed is None:
            return

        targets = parsed["targets"]
        extra_args = parsed["extra_args"]
        timeout_seconds = parsed["timeout"]
        passive = parsed["payload"].get("passive", False)

        _ensure_dirs()
        targets_file = _write_targets_file(targets)
        command, output_file = _build_command(targets_file, extra_args, passive=passive)

        print(f"[scan] targets={targets} passive={passive} timeout={timeout_seconds}s", flush=True)

        completed = self._run_tool("nuclei", command, timeout_seconds)
        if completed is None:
            return

        findings = _parse_findings(completed.stdout or "")
        stats = _parse_stats(completed.stderr or "")

        print(f"[scan] completed exit_code={completed.returncode} findings={len(findings)} templates={stats.get('templates', '?')}", flush=True)

        self._send_json(
            HTTPStatus.OK,
            {
                "target": targets[0] if len(targets) == 1 else targets,
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

    # ------------------------------------------------------------------
    # /probe — httpx
    # ------------------------------------------------------------------

    def _handle_probe(self) -> None:
        parsed = self._parse_request()
        if parsed is None:
            return

        targets = parsed["targets"]
        extra_args = parsed["extra_args"]
        timeout_seconds = parsed["timeout"]
        payload = parsed["payload"]

        _ensure_dirs()
        targets_file = _write_targets_file(targets)

        per_host_timeout = str(payload.get("per_host_timeout", 10))

        command = [
            "httpx",
            "-l", str(targets_file),
            "-json",
            "-silent",
            "-status-code",
            "-title",
            "-tech-detect",
            "-content-type",
            "-follow-redirects",
            "-timeout", per_host_timeout,
        ]
        if extra_args:
            command.extend(shlex.split(extra_args))

        print(f"[probe] targets={targets} timeout={timeout_seconds}s", flush=True)

        completed = self._run_tool("httpx", command, timeout_seconds)
        if completed is None:
            return

        results = _parse_jsonl(completed.stdout or "")

        print(f"[probe] completed exit_code={completed.returncode} results={len(results)}", flush=True)

        self._send_json(
            HTTPStatus.OK,
            {
                "results": results,
                "count": len(results),
                "exit_code": completed.returncode,
            },
        )

    # ------------------------------------------------------------------
    # /crawl — katana
    # ------------------------------------------------------------------

    def _handle_crawl(self) -> None:
        parsed = self._parse_request()
        if parsed is None:
            return

        targets = parsed["targets"]
        extra_args = parsed["extra_args"]
        timeout_seconds = parsed["timeout"]
        payload = parsed["payload"]

        _ensure_dirs()
        targets_file = _write_targets_file(targets)

        depth = str(payload.get("depth", 3))

        command = [
            "katana",
            "-list", str(targets_file),
            "-json",
            "-silent",
            "-depth", depth,
            "-js-crawl",
            "-known-files", "all",
        ]
        if extra_args:
            command.extend(shlex.split(extra_args))

        print(f"[crawl] targets={targets} depth={depth} timeout={timeout_seconds}s", flush=True)

        completed = self._run_tool("katana", command, timeout_seconds)
        if completed is None:
            return

        raw_results = _parse_jsonl(completed.stdout or "")

        endpoints = []
        for obj in raw_results:
            req = obj.get("request", {})
            resp = obj.get("response", {})
            endpoints.append({
                "url": req.get("endpoint", obj.get("url", "")),
                "method": req.get("method", "GET"),
                "source": obj.get("source", ""),
                "tag": req.get("tag", obj.get("tag", "")),
                "status_code": resp.get("status_code"),
            })

        print(f"[crawl] completed exit_code={completed.returncode} endpoints={len(endpoints)}", flush=True)

        self._send_json(
            HTTPStatus.OK,
            {
                "target": targets[0] if len(targets) == 1 else targets,
                "endpoints": endpoints,
                "count": len(endpoints),
                "exit_code": completed.returncode,
            },
        )



def main() -> None:
    _ensure_dirs()
    server = ThreadingHTTPServer((HOST, PORT), NucleiAPIHandler)
    print(f"PD Tools API listening on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
