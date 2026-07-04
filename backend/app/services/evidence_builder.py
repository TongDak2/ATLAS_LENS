from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.core.security import stable_hash
from app.models import Evidence


def ts_to_iso(value: Any) -> str | None:
    try:
        if value is None:
            return None
        if isinstance(value, str) and value.strip().isdigit():
            value = int(value.strip())
        if isinstance(value, int):
            if value <= 0:
                return None
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        return date_like_to_iso(str(value))
    except Exception:
        return None


def date_like_to_iso(value: str) -> str | None:
    v = value.strip()
    for fmt in ("%Y-%m-%d", "%Y-%m", "%Y/%m/%d", "%Y.%m.%d"):
        try:
            d = datetime.strptime(v, fmt)
            return d.replace(tzinfo=timezone.utc).isoformat()
        except Exception:
            pass
    return v if v else None


def _first(item: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for k in keys:
        if item.get(k) not in (None, ""):
            return item.get(k)
    return default


def make_evidence_from_items(module: str, query: str, items: list[dict[str, Any]], start_index: int = 1) -> list[Evidence]:
    out: list[Evidence] = []
    mod = module.lower()
    for idx, item in enumerate(items, start_index):
        eid = f"S{idx}"
        raw_ref = str(item.get("id") or stable_hash(str(item)))
        if mod == "cl":
            title = "Credential exposure observed"
            domain = _first(item, "domain", default="unknown")
            email = _first(item, "email", "user", default="masked")
            source = _first(item, "leaked_from", "source", default="unknown")
            summary = f"유출 계정 정황 확인: domain={domain}, email={email}, source={source}"
            ev_type = "credential_exposure"
            sev = "high"
            conf = 0.82
            event_time = ts_to_iso(_first(item, "leaked_date", "leakedDate", "leakeddate"))
        elif mod == "cb":
            title = "Combo credential reuse signal"
            user = _first(item, "user", "email", "id", default="masked")
            summary = f"ID/PW 조합 노출 신호 확인: user={user}"
            ev_type = "combo_exposure"
            sev = "medium"
            conf = 0.72
            event_time = ts_to_iso(_first(item, "leakeddate", "leaked_date", "LeakedDate"))
        elif mod == "cds":
            title = "Stealer-infected endpoint trace"
            host = _first(item, "host", "url", default="unknown")
            user = _first(item, "user", "email", default="masked")
            computer = _first(item, "computername", "computerName", "hostname", default="unknown")
            ip = _first(item, "ip", default="unknown")
            summary = f"감염 단말 기반 계정/호스트 노출 흔적 확인: host={host}, user={user}, computer={computer}, ip={ip}"
            ev_type = "stealer_exposure"
            sev = "critical"
            conf = 0.88
            event_time = ts_to_iso(_first(item, "leakeddate", "leaked_date", "regdate"))
        elif mod == "rm":
            title = "Ransomware monitoring signal"
            victim = _first(item, "victim", "title", default="unknown victim")
            group = _first(item, "attackGroup", "attack_group", "author", default="unknown actor")
            site = _first(item, "site", default="unknown site")
            summary = f"랜섬웨어 공개/인접 피해 정황 관측: victim={victim}, group={group}, site={site}"
            ev_type = "ransomware_mention"
            sev = "high"
            conf = 0.68
            event_time = ts_to_iso(_first(item, "detection_datetime", "detectionTime"))
        elif mod == "lm":
            title = "Leaked monitoring mention"
            mention = _first(item, "title", "value", default="untitled")
            author = _first(item, "author", default="unknown")
            summary = f"기업/산업군 유출 또는 협박성 언급 관측: {mention} / author={author}"
            ev_type = "leak_mention"
            sev = "medium"
            conf = 0.64
            event_time = ts_to_iso(_first(item, "detection_datetime", "detectionTime"))
        elif mod == "gm":
            title = "Government monitoring mention"
            mention = _first(item, "title", "value", default="untitled")
            author = _first(item, "author", default="unknown")
            summary = f"정부·공공 관련 위협 언급 관측: {mention} / author={author}"
            ev_type = "leak_mention"
            sev = "medium"
            conf = 0.66
            event_time = ts_to_iso(_first(item, "detection_datetime", "detectionTime"))
        elif mod == "tt":
            title = "Telegram threat mention"
            value = _first(item, "title", "value", "highlight", default="masked mention")
            target = _first(item, "_target", default="telegram")
            summary = f"텔레그램 기반 위협 언급 관측: target={target}, value={value}"
            ev_type = "telegram_mention"
            sev = "medium"
            conf = 0.55
            event_time = ts_to_iso(_first(item, "detection_datetime", "createDate", "create_date"))
        else:
            title = f"{module} evidence"
            summary = str(item)[:240]
            ev_type = "unknown"
            sev = "info"
            conf = 0.5
            event_time = None
        out.append(Evidence(
            id=eid,
            source=f"StealthMole {module.upper()}",
            module=module.upper(),
            evidence_type=ev_type,
            title=title,
            summary=summary,
            query=query,
            confidence=conf,
            severity=sev,
            citation=f"[{eid}]",
            raw_ref=raw_ref,
            event_time=event_time,
            metadata={"raw": item},
            redacted=True,
        ))
    return out
