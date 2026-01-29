#!/usr/bin/env python3
import hashlib
import json
import os
import subprocess
import uuid
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional


DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
LOG_DIR = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))
CONFIG_FILE = os.getenv("NUCLEI_CONFIG", "/etc/nuclei/config.yaml")
TEMPLATE_PATHS = ["/root/nuclei-templates"]
HOST = os.getenv("NUCLEI_API_HOST", "0.0.0.0")
PORT = int(os.getenv("NUCLEI_API_PORT", "8080"))


def _ensure_dirs() -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _detect_version() -> str:
    try:
        completed = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            check=False,
        )
        output = completed.stdout.strip() or completed.stderr.strip()
        return output.splitlines()[0] if output else "unknown"
    except OSError:
        return "unknown"


def _short_id(*parts: str) -> str:
    payload = "|".join(parts).encode("utf-8")
    return hashlib.sha1(payload).hexdigest()[:12]


def normalize_nuclei_jsonl(jsonl_path: str, scan_id: str) -> List[Dict[str, Any]]:
    findings = []
    path = Path(jsonl_path)
    if not path.exists():
        return findings
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("type") == "stats":
                continue

            info = record.get("info") or {}
            template_id = record.get("template-id") or record.get("templateID") or record.get("template") or "unknown"
            matched_at = record.get("matched-at") or record.get("matched") or record.get("url") or record.get("host")
            host = record.get("host") or record.get("hostname") or record.get("ip") or "unknown"
            ip_addr = record.get("ip") if record.get("ip") else None
            severity = info.get("severity") or "info"
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [tag.strip() for tag in tags.split(",") if tag.strip()]

            description = info.get("description") or info.get("name") or "Nuclei finding"
            references = info.get("reference") or info.get("references") or []
            if isinstance(references, str):
                references = [references]
            classification = info.get("classification") or {}
            cwe_ids = classification.get("cwe-id") or classification.get("cwe") or []
            if isinstance(cwe_ids, str):
                cwe_ids = [cwe_ids]
            for cwe in cwe_ids:
                references.append(f"CWE-{cwe}".replace("CWE-CWE-", "CWE-"))

            remediation_summary = description if info.get("description") else None
            confidence = "low"
            if remediation_summary and references:
                confidence = "high"
            elif remediation_summary or references:
                confidence = "medium"

            detected_at = record.get("timestamp") or record.get("time") or _now_iso()

            finding = {
                "finding_id": _short_id(scan_id, template_id, str(matched_at), str(host)),
                "scan_id": scan_id,
                "asset": {
                    "host": host,
                    "ip": ip_addr,
                    "matched_at": matched_at,
                },
                "template": {
                    "id": template_id,
                    "name": info.get("name") or template_id,
                    "category": record.get("type") or "unknown",
                    "severity": severity,
                    "tags": tags,
                },
                "description": description,
                "remediation": {
                    "summary": remediation_summary,
                    "confidence": confidence,
                    "references": references,
                },
                "timestamps": {
                    "detected_at": detected_at,
                },
                "raw": record,
            }
            findings.append(finding)
    return findings


def _load_stats(jsonl_path: str) -> Dict[str, int]:
    stats = {"templates_loaded": 0, "requests_sent": 0, "hosts_seen": 0}
    path = Path(jsonl_path)
    if not path.exists():
        return stats
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("type") == "stats":
                payload = record.get("stats") or {}
                stats["templates_loaded"] = int(payload.get("templates", 0))
                stats["requests_sent"] = int(payload.get("requests", 0))
                stats["hosts_seen"] = int(payload.get("hosts", 0))
                break
    return stats


def build_scan_summary(findings: List[Dict[str, Any]], stats: Dict[str, int]) -> Dict[str, Any]:
    severity_counts = {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
    for finding in findings:
        severity = finding.get("template", {}).get("severity", "info")
        if severity not in severity_counts:
            severity = "info"
        severity_counts[severity] += 1
    return {
        "coverage": {
            "templates_loaded": stats.get("templates_loaded", 0),
            "requests_sent": stats.get("requests_sent", 0),
            "hosts_seen": stats.get("hosts_seen", 0),
            "passive_only": True,
        },
        "summary": {
            "total_findings": len(findings),
            "severity_counts": severity_counts,
        },
    }


class NucleiAPIHandler(BaseHTTPRequestHandler):
    def _send_json(self, status: HTTPStatus, payload: Dict[str, Any]) -> None:
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

        target = payload.get("target")
        if not target or not isinstance(target, str):
            self._bad_request("Field 'target' must be a non-empty string")
            return

        _ensure_dirs()
        scan_id = uuid.uuid4().hex
        output_file = LOG_DIR / f"passive-api-{scan_id}.jsonl"
        started_at = _now_iso()

        command = [
            "nuclei",
            "-passive",
            "-jsonl",
            "-silent",
            "-config",
            CONFIG_FILE,
            "-output",
            str(output_file),
            "-u",
            target.strip(),
        ]

        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
        )
        completed_at = _now_iso()

        stats = _load_stats(str(output_file))
        findings = normalize_nuclei_jsonl(str(output_file), scan_id)
        summary_payload = build_scan_summary(findings, stats)

        response = {
            "scan": {
                "scan_id": scan_id,
                "mode": "passive",
                "targets": [target.strip()],
                "started_at": started_at,
                "completed_at": completed_at,
                "duration_ms": int(
                    (datetime.fromisoformat(completed_at) - datetime.fromisoformat(started_at)).total_seconds()
                    * 1000
                ),
                "exit_code": completed.returncode,
            },
            "environment": {
                "scanner": "nuclei",
                "scanner_version": _detect_version(),
                "config_path": CONFIG_FILE,
                "template_paths": TEMPLATE_PATHS,
            },
            "coverage": summary_payload["coverage"],
            "summary": summary_payload["summary"],
            "findings": findings,
        }

        self._send_json(HTTPStatus.OK, response)


def main() -> None:
    _ensure_dirs()
    server = ThreadingHTTPServer((HOST, PORT), NucleiAPIHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
