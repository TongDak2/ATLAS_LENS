from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import re
from urllib.parse import urlparse

from app.connectors.stealthmole import StealthMoleClient, safe_items
from app.core.config import settings
from app.models import Evidence, InvestigationPlanStep, InvestigationRequest
from app.services.atlas_engine import assemble_result
from app.services.entity_extractor import extract_entities
from app.services.evidence_builder import make_evidence_from_items
from app.services.planner import build_plan
from app.services.public_surface import build_target_profile, collect_public_surface, make_public_surface_evidence
from app.services.query_normalizer import normalize_query


class Investigator:
    def __init__(self) -> None:
        self.stealth = StealthMoleClient()

    def _window(self, days: int) -> tuple[int, int]:
        if days <= 0:
            return 0, 0
        end = int(datetime.now(timezone.utc).timestamp())
        start = int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())
        return start, end

    def _run_step_live(self, step: InvestigationPlanStep, limit: int, start: int, end: int) -> tuple[list[dict], str]:
        m = step.module.lower()
        if m in {"cl", "cb"}:
            resp = self.stealth.search_sync(m, step.query, limit=limit, start=start, end=end)
            items = safe_items(resp)
            return items, _reason_from_response(resp, len(items))
        if m == "cds":
            resp = self.stealth.search_sync(m, step.query, limit=limit, start=start, end=end, include_gps=False)
            items = safe_items(resp)
            return items, _reason_from_response(resp, len(items))
        if m in {"rm", "lm", "gm"}:
            resp = self.stealth.search_monitoring(m, step.query, limit=limit, start=start, end=end)
            items = safe_items(resp)
            return items, _reason_from_response(resp, len(items))
        if m == "tt":
            indicator, text = _infer_async_indicator(step.query)
            resp = self.stealth.search_async(
                "tt",
                indicator=indicator,
                text=text,
                limit=limit,
                start=start,
                end=end,
                poll_attempts=settings.stealthmole_async_poll_attempts,
            )
            items = safe_items(resp)
            return items, _reason_from_response(resp, len(items), async_module=True)
        return [], "module not supported in live execution"

    def investigate(self, req: InvestigationRequest):
        normalized = normalize_query(req.query)
        effective_req = req.model_copy(update={"query": normalized.query})
        entities = extract_entities(effective_req.query)
        profile = build_target_profile(
            original_query=normalized.original_query,
            normalized_query=normalized.query,
            query_was_expanded=normalized.query_was_expanded,
            default_mission_applied=normalized.default_mission_applied,
            entities=entities,
        )
        plan = build_plan(entities, req.max_results_per_source, effective_req.query)
        all_ev: list[Evidence] = []
        next_idx = 1
        use_live = req.live
        start, end = self._window(req.time_window_days)

        if use_live and req.include_public_feeds:
            profile = collect_public_surface(profile)
            pub_ev = make_public_surface_evidence(profile, start_index=next_idx)
            next_idx += len(pub_ev)
            all_ev.extend(pub_ev)

        if use_live and not self.stealth.configured:
            for step in plan:
                step.status = "failed"
                step.reason = "StealthMole credentials are not configured; live evidence was not fabricated."
            return assemble_result(effective_req, entities, plan, all_ev, profile)

        if not use_live:
            for step in plan:
                step.status = "skipped"
                step.reason = "live=false; no API query executed and no evidence fabricated"
            return assemble_result(effective_req, entities, plan, all_ev, profile)

        for step in plan:
            module = step.module.lower()
            if module in {"cisa_kev", "epss"}:
                step.status = "skipped"
                step.reason = "Public CVE feed enrichment is only used when CVEs are explicit."
                continue
            try:
                items, reason = self._run_step_live(step, req.max_results_per_source, start, end)
                raw_count = len(items)
                items = _filter_items_for_step(step, items)
                if raw_count != len(items):
                    reason = f"{reason}; exact-domain-filtered={len(items)}/{raw_count}"
                ev = make_evidence_from_items(module, step.query, items, start_index=next_idx)
                next_idx += len(ev)
                all_ev.extend(ev)
                step.status = "completed"
                step.reason = reason
            except Exception as e:
                step.status = "failed"
                step.reason = f"{type(e).__name__}: {e}"
        return assemble_result(effective_req, entities, plan, all_ev, profile)


def _reason_from_response(resp: dict, item_count: int, async_module: bool = False) -> str:
    status = resp.get("status_code")
    if not resp.get("ok"):
        detail = resp.get("data", {}).get("detail") if isinstance(resp.get("data"), dict) else resp.get("error")
        return f"API status={status}; {detail or 'no live evidence returned'}"
    data = resp.get("data")
    total = None
    if isinstance(data, dict):
        total = data.get("totalCount")
        if total is None:
            totals = []
            for value in data.values():
                if isinstance(value, dict) and isinstance(value.get("totalCount"), int):
                    totals.append(value["totalCount"])
            if totals:
                total = sum(totals)
    mode = "async live" if async_module else "live"
    if total is not None:
        return f"{item_count} {mode} evidence items normalized; totalCount={total}"
    return f"{item_count} {mode} evidence items normalized"


def _infer_async_indicator(query: str) -> tuple[str, str]:
    q = query.strip()
    if q.startswith("domain:"):
        return "domain", q.split(":", 1)[1]
    if q.startswith("url:"):
        return "url", q.split(":", 1)[1]
    if q.startswith("email:"):
        return "email", q.split(":", 1)[1]
    if q.startswith("ip:"):
        return "ip", q.split(":", 1)[1]
    if "." in q and " " not in q:
        return "domain", q
    return "keyword", q


def _filter_items_for_step(step: InvestigationPlanStep, items: list[dict]) -> list[dict]:
    if step.query.startswith("domain:"):
        domain = step.query.split(":", 1)[1].strip().lower()
        if not domain:
            return items
        return [item for item in items if _item_matches_domain(item, domain)]
    if step.query.startswith("ip:"):
        ip = step.query.split(":", 1)[1].strip()
        if not ip:
            return items
        return [item for item in items if _item_matches_ip(item, ip)]
    return items


def _item_matches_domain(item: dict, domain: str) -> bool:
    # Structured fields first. Avoid substring false positives such as grand4d.tech for d4d.tech.
    for key in ("domain", "site", "host", "url", "proof_url"):
        value = item.get(key)
        if isinstance(value, str) and _value_matches_domain(value, domain):
            return True
    for key in ("email", "user", "id", "username"):
        value = item.get(key)
        if isinstance(value, str) and "@" in value:
            mail_domain = value.rsplit("@", 1)[1].lower().strip()
            if mail_domain == domain or mail_domain.endswith("." + domain):
                return True
    # Monitoring titles may only contain text. Use boundary-aware domain matching.
    text = json.dumps(item, ensure_ascii=False, default=str).lower()
    pattern = re.compile(rf"(?<![a-z0-9-])(?:[a-z0-9-]+\.)*{re.escape(domain)}(?![a-z0-9-])")
    return bool(pattern.search(text))


def _item_matches_ip(item: dict, ip: str) -> bool:
    for key in ("ip", "client_ip", "source_ip", "remote_ip", "host", "url", "proof_url"):
        value = item.get(key)
        if isinstance(value, str) and _value_matches_ip(value, ip):
            return True
    text = json.dumps(item, ensure_ascii=False, default=str)
    return bool(re.search(rf"(?<!\d){re.escape(ip)}(?!\d)", text))


def _value_matches_ip(value: str, ip: str) -> bool:
    v = value.strip()
    if "://" in v:
        parsed = urlparse(v)
        host = parsed.netloc.split(":", 1)[0] if parsed.netloc else v
    else:
        host = v.split("/", 1)[0].split(":", 1)[0]
    return host == ip or bool(re.search(rf"(?<!\d){re.escape(ip)}(?!\d)", v))


def _value_matches_domain(value: str, domain: str) -> bool:
    v = value.strip().lower()
    if "://" in v:
        parsed = urlparse(v)
        host = parsed.netloc.split(":", 1)[0].lower() if parsed.netloc else v
    else:
        host = v.split("/", 1)[0].split(":", 1)[0]
    if host.startswith("www."):
        host = host[4:]
    return host == domain or host.endswith("." + domain)
