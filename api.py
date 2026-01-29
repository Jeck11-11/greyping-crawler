import os
import re
from ipaddress import ip_address
from typing import List, Optional

from celery import Celery
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from redis import Redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_BACKEND_URL = os.getenv("CELERY_BACKEND_URL", REDIS_URL)
RATE_LIMIT_COUNT = int(os.getenv("RATE_LIMIT_COUNT", "5"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

celery_app = Celery("nuclei_tasks", broker=CELERY_BROKER_URL, backend=CELERY_BACKEND_URL)
redis_client = Redis.from_url(REDIS_URL, decode_responses=True)

app = FastAPI(title="Nuclei Scan API")

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
ALLOWED_TEMPLATES = {"cves", "dns", "http", "cloud", "network"}


class ScanRequest(BaseModel):
    target: str = Field(..., min_length=1)
    mode: str = Field("passive", pattern="^(passive|active|full)$")
    templates: Optional[List[str]] = None
    extra_args: Optional[str] = None


def _normalize_target(target: str) -> str:
    cleaned = target.strip().lower()
    cleaned = cleaned.replace("https://", "").replace("http://", "")
    cleaned = cleaned.strip("/")
    return cleaned


def _is_valid_target(target: str) -> bool:
    if not target:
        return False
    try:
        ip_address(target)
        return True
    except ValueError:
        return bool(DOMAIN_REGEX.match(target))


def _rate_limit_key(ip: str) -> str:
    return f"rate:{ip}"


def _check_rate_limit(client_ip: str) -> None:
    key = _rate_limit_key(client_ip)
    count = redis_client.incr(key)
    if count == 1:
        redis_client.expire(key, RATE_LIMIT_WINDOW)
    if count > RATE_LIMIT_COUNT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded")


@app.post("/scan")
async def scan(request: Request, payload: ScanRequest):
    client_ip = request.client.host if request.client else "unknown"
    _check_rate_limit(client_ip)

    target = _normalize_target(payload.target)
    if not _is_valid_target(target):
        raise HTTPException(status_code=400, detail="Invalid target domain or IP")
    if payload.templates:
        normalized_templates = {template.strip().lower() for template in payload.templates}
        if not normalized_templates.issubset(ALLOWED_TEMPLATES):
            raise HTTPException(status_code=400, detail="Invalid template group requested")

    task = celery_app.send_task(
        "worker.run_scan",
        kwargs={
            "target": target,
            "mode": payload.mode,
            "templates": payload.templates,
            "extra_args": payload.extra_args,
        },
    )
    return {"task_id": task.id, "status": "queued"}


@app.get("/health")
async def health():
    return {"status": "ok"}
