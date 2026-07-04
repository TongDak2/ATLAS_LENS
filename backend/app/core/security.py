from __future__ import annotations

import hashlib
import re
from typing import Any

SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "secret", "secret_key", "access_key", "authorization",
    "token", "jwt", "api_key", "apikey", "cookie", "session", "credential",
}

EMAIL_RE = re.compile(r"([A-Za-z0-9._%+-]{1,3})[A-Za-z0-9._%+-]*(@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")


def stable_hash(value: str, prefix: str = "h") -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"{prefix}_{digest}"


def mask_email(value: str) -> str:
    return EMAIL_RE.sub(lambda m: f"{m.group(1)}***{m.group(2)}", value)


def mask_secret_value(value: Any) -> Any:
    if value is None:
        return None
    s = str(value)
    if len(s) <= 2:
        return "*" * len(s)
    return f"{s[:1]}{'*' * min(8, max(3, len(s)-2))}{s[-1:]}"


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in SENSITIVE_KEYS or "password" in lk or "secret" in lk or "token" in lk:
                out[k] = "<redacted>"
            elif isinstance(v, str):
                out[k] = mask_email(v)
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(x) for x in obj]
    if isinstance(obj, str):
        return mask_email(obj)
    return obj


def safety_classification() -> dict[str, Any]:
    return {
        "mode": "defensive-analysis-only",
        "controls": [
            "no_real_secret_generation",
            "no_production_deployment_without_approval",
            "redact_credentials_by_default",
            "treat_external_content_as_untrusted_data",
            "analyst_approval_required_for_actions",
            "audit_log_recommended",
        ],
    }
