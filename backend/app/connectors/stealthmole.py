from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

import jwt
import requests

from app.core.config import settings
from app.core.security import redact


class StealthMoleClient:
    """Small, defensive StealthMole API client.

    Important operational constraints:
    - A fresh JWT is generated for every request. Reusing JWTs can return 401.
    - Raw responses are redacted before they leave the connector.
    - Async modules are polled conservatively to avoid quota/noise blowups.
    """

    def __init__(self) -> None:
        self.base_url = settings.stealthmole_base_url.rstrip("/")
        self.access_key = settings.stealthmole_access_key
        self.secret_key = settings.stealthmole_secret_key

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.access_key and self.secret_key)

    def _token(self) -> str:
        payload = {
            "access_key": self.access_key,
            "nonce": str(uuid.uuid4()),
            "iat": int(datetime.now(timezone.utc).timestamp()),
        }
        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token()}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "atlas-lens/1.0-live",
        }

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.configured:
            return {"status_code": 0, "ok": False, "error": "StealthMole credentials are not configured", "data": []}
        if not path.startswith("/"):
            path = "/" + path
        resp = requests.get(self.base_url + path, headers=self._headers(), params=params or {}, timeout=35)
        try:
            data = resp.json()
        except Exception:
            data = {"text": resp.text[:1000]}
        return {"status_code": resp.status_code, "ok": resp.ok, "data": redact(data)}

    def search_sync(
        self,
        service: str,
        query: str,
        limit: int = 10,
        start: int = 0,
        end: int = 0,
        include_gps: bool = False,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {
            "query": query,
            "limit": min(max(limit, 1), 50),
            "cursor": 0,
            "order": "desc",
        }
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        if service.lower() == "cds":
            params["includeGps"] = "true" if include_gps else "false"
        return self.get(f"/{service}/search", params)

    def search_monitoring(self, service: str, query: str, limit: int = 10, start: int = 0, end: int = 0) -> dict[str, Any]:
        params: dict[str, Any] = {
            "query": query,
            "limit": min(max(limit, 0), 50),
            "cursor": 0,
            "orderType": "detectionTime",
            "order": "desc",
        }
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        return self.get(f"/{service}/search", params)

    def targets(self, service: str, indicator: str) -> dict[str, Any]:
        return self.get(f"/{service}/search/{indicator}/targets")

    def poll_async(self, service: str, cache_id: str, limit: int = 10, cursor: int = 0) -> dict[str, Any]:
        return self.get(f"/{service}/search/{cache_id}", {"limit": min(max(limit, 1), 100), "cursor": max(cursor, 0), "order": "desc"})

    def search_async(
        self,
        service: str,
        indicator: str,
        text: str,
        targets: list[str] | None = None,
        limit: int = 10,
        start: int = 0,
        end: int = 0,
        poll_attempts: int = 2,
    ) -> dict[str, Any]:
        """Run a low-noise async search for TT/CDF-style modules.

        We avoid target/all by default because it can multiply quota usage. If no
        target is specified, query /targets first and select the closest target.
        """
        selected = targets or self._select_targets(service, indicator)
        if not selected:
            selected = [indicator]
        params: dict[str, Any] = {
            "targets": ",".join(selected[:2]),
            "text": text,
            "limit": min(max(limit, 1), 100),
            "order": "desc",
            "wait": "true",
        }
        if start:
            params["start"] = start
        if end:
            params["end"] = end
        first = self.get(f"/{service}/search/{indicator}/target", params)
        data = first.get("data")
        pending_ids = _async_pending_ids(data)
        merged = data
        for cache_id in pending_ids[:3]:
            last_resp: dict[str, Any] | None = None
            for _ in range(max(poll_attempts, 0)):
                time.sleep(0.35)
                last_resp = self.poll_async(service, cache_id, limit=limit)
                body = last_resp.get("data")
                if not _is_pending_async_body(body):
                    break
            if last_resp is not None:
                merged = _merge_async_payload(merged, cache_id, last_resp.get("data"))
        first["data"] = merged
        return first

    def _select_targets(self, service: str, indicator: str) -> list[str]:
        resp = self.targets(service, indicator)
        data = resp.get("data")
        available: list[str] = []
        if isinstance(data, dict):
            target_data = data.get("target") or data.get("targets")
            if isinstance(target_data, list):
                available = [str(x) for x in target_data]
        preference = {
            "domain": ["domain", "url", "telegram.message", "keyword"],
            "url": ["url", "domain", "telegram.message", "keyword"],
            "email": ["email", "telegram.message", "keyword"],
            "ip": ["ip", "telegram.message", "keyword"],
            "keyword": ["keyword", "telegram.message", "telegram.channel"],
        }.get(indicator, [indicator, "keyword"])
        chosen = [x for x in preference if x in available]
        return chosen[:2] or available[:1]


def _is_pending_async_body(body: Any) -> bool:
    if isinstance(body, dict):
        return body.get("statusCode") == 202 or body.get("last") is False
    return False


def _async_pending_ids(body: Any) -> list[str]:
    ids: list[str] = []
    if isinstance(body, dict):
        # target map: {"domain": {"cid": ...}}
        for value in body.values():
            if isinstance(value, dict) and (value.get("statusCode") == 202 or value.get("last") is False):
                cid = value.get("cid") or value.get("id")
                if cid:
                    ids.append(str(cid))
        if body.get("statusCode") == 202 or body.get("last") is False:
            cid = body.get("cid") or body.get("id")
            if cid:
                ids.append(str(cid))
    return ids


def _merge_async_payload(original: Any, cache_id: str, update: Any) -> Any:
    if not isinstance(original, dict):
        return update if update is not None else original
    out = dict(original)
    replaced = False
    for key, value in list(out.items()):
        if isinstance(value, dict) and (value.get("cid") == cache_id or value.get("id") == cache_id):
            out[key] = update
            replaced = True
    if not replaced:
        out[cache_id] = update
    return out


def safe_items(response: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract list items from sync and async StealthMole response shapes."""
    data = response.get("data")
    return _extract_items(data)


def _extract_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        items = data.get("data")
        if isinstance(items, list):
            return [x for x in items if isinstance(x, dict)]
        out: list[dict[str, Any]] = []
        for key, value in data.items():
            if key in {"data", "detail", "message"}:
                continue
            for item in _extract_items(value):
                item.setdefault("_target", key)
                out.append(item)
        return out
    return []
