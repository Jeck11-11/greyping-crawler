"""API key authentication and rate-limiting middleware."""

from __future__ import annotations

import os
import time
from collections import defaultdict

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

# ---------------------------------------------------------------------------
# API Key Authentication
# ---------------------------------------------------------------------------

_EXEMPT_PATHS = frozenset({"/docs", "/openapi.json", "/redoc", "/health"})


def _load_api_keys() -> frozenset[str]:
    raw = os.getenv("OSINT_API_KEYS", "").strip()
    if not raw:
        return frozenset()
    return frozenset(k.strip() for k in raw.split(",") if k.strip())


class APIKeyMiddleware(BaseHTTPMiddleware):
    """Require a valid ``X-API-Key`` header.

    When ``OSINT_API_KEYS`` is unset or empty, auth is **disabled** (dev mode).
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.valid_keys = _load_api_keys()

    async def dispatch(self, request: Request, call_next):
        if not self.valid_keys:
            return await call_next(request)

        if request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        api_key = request.headers.get("x-api-key", "")
        if api_key not in self.valid_keys:
            return JSONResponse(
                status_code=401,
                content={"detail": "Invalid or missing API key"},
            )

        request.state.api_key = api_key
        return await call_next(request)


# ---------------------------------------------------------------------------
# Rate Limiting (token bucket per key / per IP)
# ---------------------------------------------------------------------------

_DEFAULT_SCAN_RPM = 60
_DEFAULT_RECON_RPM = 300


class _TokenBucket:
    __slots__ = ("capacity", "tokens", "refill_rate", "last_refill")

    def __init__(self, capacity: int) -> None:
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_rate = capacity / 60.0
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    @property
    def retry_after(self) -> int:
        if self.tokens >= 1:
            return 0
        return max(1, int((1 - self.tokens) / self.refill_rate) + 1)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-key (or per-IP) token-bucket rate limiter.

    ``/scan/*`` endpoints share one bucket; ``/recon/*`` share another.
    Limits are configured via ``RATE_LIMIT_SCAN`` and ``RATE_LIMIT_RECON``
    env vars (requests per minute). Set to ``0`` to disable.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self.scan_rpm = int(os.getenv("RATE_LIMIT_SCAN", str(_DEFAULT_SCAN_RPM)))
        self.recon_rpm = int(os.getenv("RATE_LIMIT_RECON", str(_DEFAULT_RECON_RPM)))
        self._scan_buckets: dict[str, _TokenBucket] = defaultdict(
            lambda: _TokenBucket(self.scan_rpm)
        )
        self._recon_buckets: dict[str, _TokenBucket] = defaultdict(
            lambda: _TokenBucket(self.recon_rpm)
        )

    def _identity(self, request: Request) -> str:
        return getattr(request.state, "api_key", None) or (
            request.client.host if request.client else "unknown"
        )

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if path.startswith("/scan") and self.scan_rpm > 0:
            bucket = self._scan_buckets[self._identity(request)]
        elif path.startswith("/recon") and self.recon_rpm > 0:
            bucket = self._recon_buckets[self._identity(request)]
        else:
            return await call_next(request)

        if not bucket.consume():
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(bucket.retry_after)},
            )
        return await call_next(request)
