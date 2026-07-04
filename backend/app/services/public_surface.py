from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any

import requests

from app.core.security import stable_hash
from app.models import Entity, Evidence, TargetProfile


def build_target_profile(
    *,
    original_query: str,
    normalized_query: str,
    query_was_expanded: bool,
    default_mission_applied: bool,
    entities: list[Entity],
) -> TargetProfile:
    target = _primary_target(entities)
    profile = TargetProfile(
        kind=target.type if target else "unknown",
        value=target.value if target else "",
        display=target.display or target.value if target else "",
        original_query=original_query,
        normalized_query=normalized_query,
        query_was_expanded=query_was_expanded,
        default_mission_applied=default_mission_applied,
        collection_notes=[],
    )
    if default_mission_applied:
        profile.collection_notes.append(
            "입력이 사이트 주소 중심이라 기본 업무 시나리오를 '신규 결제 서비스 출시 전 위험 판단'으로 확장했습니다."
        )
    return profile


def collect_public_surface(profile: TargetProfile, timeout: float = 4.0) -> TargetProfile:
    """Collect a small, safe public footprint for domain targets.

    This is not a vulnerability scan. It only resolves DNS and performs one
    normal HTTPS/HTTP page fetch for public, globally routable domains so the
    report can be tied to the actual site instead of a generic template.
    """
    if profile.kind != "domain" or not profile.value:
        profile.collection_notes.append("공개 웹 표면 수집은 도메인 대상에서만 수행했습니다.")
        return profile

    domain = profile.value.lower().strip()
    addresses = _resolve_public_addresses(domain)
    surface: dict[str, Any] = {
        "domain": domain,
        "resolved_addresses": addresses[:8],
        "resolved_address_count": len(addresses),
        "http_checked": False,
    }

    if not addresses:
        profile.collection_notes.append("도메인이 공인 IP로 해석되지 않아 HTTP 표면 수집을 건너뛰었습니다.")
        profile.public_surface = surface
        return profile

    page = _fetch_landing_page(domain, timeout=timeout)
    surface.update(page)
    profile.public_surface = surface
    if page.get("ok"):
        profile.collection_notes.append("공개 DNS/웹 표면을 확인해 대상 사이트별 context에 반영했습니다.")
    else:
        profile.collection_notes.append(f"공개 DNS는 확인했지만 웹 표면 확인은 제한되었습니다: {page.get('error') or page.get('status_code')}")
    return profile


def make_public_surface_evidence(profile: TargetProfile, start_index: int = 1) -> list[Evidence]:
    surface = profile.public_surface or {}
    if not surface:
        return []
    eid = f"S{start_index}"
    domain = str(surface.get("domain") or profile.value or profile.display)
    final_url = surface.get("final_url") or surface.get("checked_url") or domain
    status = surface.get("status_code", "unknown")
    title = surface.get("title") or "title unavailable"
    address_count = surface.get("resolved_address_count", 0)
    summary = (
        f"공개 사이트 표면 확인: domain={domain}, final_url={final_url}, "
        f"status={status}, title={title}, public_ip_count={address_count}"
    )
    return [
        Evidence(
            id=eid,
            source="Public DNS/HTTP",
            module="PUBLIC",
            evidence_type="public_indicator",
            title="Public website surface resolved",
            summary=summary,
            query=f"domain:{domain}",
            confidence=0.62 if surface.get("ok") else 0.45,
            severity="info",
            citation=f"[{eid}]",
            raw_ref=stable_hash(str(surface), prefix="pub"),
            event_time=None,
            metadata={"raw": surface},
            redacted=True,
        )
    ]


def _primary_target(entities: list[Entity]) -> Entity | None:
    for typ in ("domain", "email", "ip"):
        ent = next((e for e in entities if e.type == typ), None)
        if ent:
            return ent
    return entities[0] if entities else None


def _resolve_public_addresses(domain: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP)
    except Exception:
        return []
    out: list[str] = []
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if not ip.is_global:
            continue
        text = str(ip)
        if text not in out:
            out.append(text)
    return out


def _fetch_landing_page(domain: str, timeout: float) -> dict[str, Any]:
    candidates = [f"https://{domain}/"]
    if not domain.startswith("www."):
        candidates.append(f"https://www.{domain}/")
    candidates.extend([f"http://{domain}/"])

    last_error = ""
    headers = {
        "User-Agent": "atlas-lens/1.0 public-surface-check",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    for url in candidates:
        try:
            resp = requests.get(url, headers=headers, allow_redirects=True, timeout=timeout, stream=True)
            body = resp.raw.read(192_000, decode_content=True)
            text = body.decode(resp.encoding or "utf-8", errors="ignore")
            return {
                "http_checked": True,
                "checked_url": url,
                "ok": bool(resp.ok),
                "status_code": resp.status_code,
                "final_url": resp.url,
                "content_type": resp.headers.get("Content-Type", "")[:120],
                "server": resp.headers.get("Server", "")[:120],
                "title": _extract_title(text),
            }
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"
    return {
        "http_checked": True,
        "checked_url": candidates[0],
        "ok": False,
        "error": last_error or "no HTTP response",
    }


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.I | re.S)
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:160]
