from __future__ import annotations

import hmac
import time
from dataclasses import dataclass
from threading import Lock
from typing import Annotated

from fastapi import Header, HTTPException, Request

from app.core.config import settings
from app.core.security import stable_hash


@dataclass(frozen=True)
class AuthContext:
    subject: str


_RATE_LOCK = Lock()
_RATE_BUCKETS: dict[tuple[str, str], list[float]] = {}


def _bearer_value(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def require_api_key(
    x_atlas_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> AuthContext:
    supplied = (x_atlas_api_key or _bearer_value(authorization) or "").strip()
    if not supplied:
        raise HTTPException(status_code=401, detail="Atlas API key is required")
    expected = settings.atlas_api_key.strip()
    if not expected:
        raise HTTPException(status_code=503, detail="Atlas API authentication is not configured")
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Invalid Atlas API key")
    return AuthContext(subject=stable_hash(supplied, prefix="caller"))


def enforce_rate_limit(ctx: AuthContext, request: Request, *, live: bool) -> None:
    """Small in-process guardrail for direct deployments.

    This is intentionally simple and should be complemented by a reverse proxy,
    WAF, or API gateway in production. It still prevents accidental unauthenticated
    or high-rate direct API use from burning CTI quota when the app is exposed.
    """
    window = max(settings.atlas_rate_limit_window_seconds, 1)
    limit = settings.atlas_live_rate_limit_requests if live else settings.atlas_rate_limit_requests
    limit = max(limit, 1)
    scope = "live" if live else "ops"
    client_ip = request.client.host if request.client else "unknown"
    key = (ctx.subject, f"{scope}:{client_ip}")
    now = time.monotonic()
    cutoff = now - window
    with _RATE_LOCK:
        hits = [ts for ts in _RATE_BUCKETS.get(key, []) if ts >= cutoff]
        if len(hits) >= limit:
            raise HTTPException(status_code=429, detail=f"Rate limit exceeded for {scope} requests")
        hits.append(now)
        _RATE_BUCKETS[key] = hits
