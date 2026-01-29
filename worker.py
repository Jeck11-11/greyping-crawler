import json
import os
import shlex
import subprocess
from typing import List, Optional

import requests
from celery import Celery

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_BACKEND_URL = os.getenv("CELERY_BACKEND_URL", REDIS_URL)
XANO_URL = os.getenv("XANO_URL")
XANO_API_KEY = os.getenv("XANO_API_KEY")
NUCLEI_IMAGE = os.getenv("NUCLEI_IMAGE", "projectdiscovery/nuclei")
NUCLEI_TEMPLATES_PATH = os.getenv("NUCLEI_TEMPLATES_PATH", "/opt/nuclei-templates")

celery_app = Celery("nuclei_tasks", broker=CELERY_BROKER_URL, backend=CELERY_BACKEND_URL)

TEMPLATE_MAP = {
    "cves": "/templates/cves",
    "dns": "/templates/dns",
    "http": "/templates/http",
    "cloud": "/templates/cloud",
    "network": "/templates/network",
}


def _template_args(templates: Optional[List[str]]) -> List[str]:
    if not templates:
        return ["-t", "/templates"]
    paths = []
    for template in templates:
        key = template.strip().lower()
        if key not in TEMPLATE_MAP:
            raise ValueError(f"Unknown template group: {template}")
        paths.append(TEMPLATE_MAP[key])
    return ["-t", ",".join(paths)]


def _mode_args(mode: str) -> List[str]:
    if mode == "passive":
        return ["-passive"]
    if mode == "full":
        return ["-scan-all-ips", "-scan-all-ports"]
    return []


def _extra_args(extra_args: Optional[str]) -> List[str]:
    if not extra_args:
        return []
    return shlex.split(extra_args)


def _post_to_xano(payload: dict) -> None:
    if not XANO_URL:
        return
    headers = {"Content-Type": "application/json"}
    if XANO_API_KEY:
        headers["Authorization"] = f"Bearer {XANO_API_KEY}"
    try:
        requests.post(XANO_URL, json=payload, headers=headers, timeout=10)
    except requests.RequestException as exc:
        print(f"Xano post failed: {exc}", flush=True)


def _prepull_image() -> None:
    subprocess.run(["docker", "pull", NUCLEI_IMAGE], check=False)


def _build_command(target: str, mode: str, templates: Optional[List[str]], extra_args: Optional[str]) -> List[str]:
    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{NUCLEI_TEMPLATES_PATH}:/templates:ro",
        NUCLEI_IMAGE,
        "-u",
        target,
        "-json",
    ]
    command.extend(_template_args(templates))
    command.extend(_mode_args(mode))
    command.extend(_extra_args(extra_args))
    return command


@celery_app.task(name="worker.run_scan")
def run_scan(target: str, mode: str, templates: Optional[List[str]] = None, extra_args: Optional[str] = None):
    _prepull_image()
    command = _build_command(target, mode, templates, extra_args)
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout_lines = []
    if process.stdout:
        for line in process.stdout:
            line = line.strip()
            if not line:
                continue
            stdout_lines.append(line)
            print(line, flush=True)
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                payload = {"raw": line}
            _post_to_xano(payload)

    stderr_output = process.stderr.read() if process.stderr else ""
    return_code = process.wait()

    if stderr_output:
        print(stderr_output, flush=True)

    return {
        "command": command,
        "return_code": return_code,
        "lines": len(stdout_lines),
        "stderr": stderr_output,
    }
