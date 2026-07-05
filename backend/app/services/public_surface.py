from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any
from urllib.parse import urljoin, urlparse

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
            "입력이 사이트 주소 중심이라 기본 임무 시나리오를 '연합훈련 전 Mission Exposure Gate'로 확장했습니다."
        )
    return profile


def collect_public_surface(profile: TargetProfile, timeout: float = 4.0) -> TargetProfile:
    """Collect a small, safe public footprint for concrete indicators.

    This is not a vulnerability scan. It only resolves DNS and performs one
    normal HTTPS/HTTP page fetch for public, globally routable domains. Email
    targets verify their domain. IP targets are checked for global routability.
    """
    if not profile.value:
        profile.collection_notes.append("검증할 대상 지표가 없어 공개 표면 수집을 건너뛰었습니다.")
        return profile

    if profile.kind == "ip":
        profile.public_surface = _verify_ip_surface(profile.value)
        if profile.public_surface.get("target_verified"):
            profile.collection_notes.append("입력 IP가 공인 라우팅 가능한 주소로 확인되었습니다.")
        else:
            profile.collection_notes.append("입력 IP가 공인 라우팅 가능한 주소로 확인되지 않아 GO 판단에서 제외했습니다.")
        return profile

    domain = _domain_for_profile(profile)
    if not domain:
        profile.collection_notes.append("도메인 또는 이메일 도메인을 추출하지 못해 대상 검증을 수행하지 못했습니다.")
        profile.public_surface = {"indicator_kind": profile.kind, "target_verified": False, "verification_status": "no-domain"}
        return profile

    addresses = _resolve_public_addresses(domain)
    surface: dict[str, Any] = {
        "indicator_kind": profile.kind,
        "domain": domain,
        "resolved_addresses": addresses[:8],
        "resolved_address_count": len(addresses),
        "target_verified": bool(addresses),
        "verification_status": "public-dns-resolved" if addresses else "unresolved-public-dns",
        "http_checked": False,
    }

    if not addresses:
        profile.collection_notes.append("대상 도메인이 공인 IP로 해석되지 않아 GO 판단에서 제외했습니다.")
        profile.public_surface = surface
        return profile

    if profile.kind == "email":
        profile.collection_notes.append("이메일 도메인이 공인 DNS로 해석되어 대상 context에 반영했습니다.")
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
    indicator_kind = str(surface.get("indicator_kind") or profile.kind)
    indicator = str(surface.get("domain") or surface.get("ip") or profile.value or profile.display)
    final_url = surface.get("final_url") or surface.get("checked_url") or indicator
    status = surface.get("status_code", "unknown")
    title = surface.get("title") or "title unavailable"
    address_count = surface.get("resolved_address_count", 0)
    verified = bool(surface.get("target_verified"))
    summary = (
        f"대상 지표 검증: kind={indicator_kind}, indicator={indicator}, "
        f"verified={verified}, status={surface.get('verification_status', 'unknown')}, "
        f"landing={final_url}, http={status}, title={title}, public_ip_count={address_count}"
    )
    return [
        Evidence(
            id=eid,
            source="Public DNS/HTTP/IP verification",
            module="PUBLIC",
            evidence_type="public_indicator",
            title="Target indicator verified" if verified else "Target indicator could not be verified",
            summary=summary,
            query=f"{indicator_kind}:{indicator}",
            confidence=0.62 if verified else 0.35,
            severity="info",
            citation=f"[{eid}]",
            raw_ref=stable_hash(str(surface), prefix="pub"),
            event_time=None,
            metadata={"raw": surface},
            redacted=True,
        )
    ]


def _primary_target(entities: list[Entity]) -> Entity | None:
    # Preserve the operator's concrete indicator type. Email extraction also
    # emits the email domain for enrichment, but the investigation target should
    # remain the email address when that is what the operator typed.
    return next((e for e in entities if e.type in {"email", "domain", "ip"}), entities[0] if entities else None)


def _domain_for_profile(profile: TargetProfile) -> str:
    if profile.kind == "domain":
        return profile.value.lower().strip()
    if profile.kind == "email" and "@" in profile.value:
        return profile.value.rsplit("@", 1)[1].lower().strip()
    return ""


def _verify_ip_surface(value: str) -> dict[str, Any]:
    try:
        ip = ipaddress.ip_address(value.strip().strip("[]").split("%", 1)[0])
    except ValueError:
        return {
            "indicator_kind": "ip",
            "ip": value,
            "target_verified": False,
            "verification_status": "invalid-ip",
            "http_checked": False,
        }
    return {
        "indicator_kind": "ip",
        "ip": str(ip),
        "target_verified": bool(ip.is_global),
        "verification_status": "global-ip" if ip.is_global else "non-public-ip",
        "http_checked": False,
    }


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
        result = _fetch_safe_url(url, headers=headers, timeout=timeout)
        if result.get("ok") or result.get("status_code"):
            return result
        last_error = str(result.get("error") or "")
    return {
        "http_checked": True,
        "checked_url": candidates[0],
        "ok": False,
        "error": last_error or "no HTTP response",
    }


def _fetch_safe_url(url: str, *, headers: dict[str, str], timeout: float, max_redirects: int = 3) -> dict[str, Any]:
    """Fetch one public HTTP(S) URL while guarding against SSRF-style redirects.

    The public surface collector is intentionally lightweight, but redirects can
    otherwise pivot a harmless public domain request to localhost, link-local, or
    private addresses. Before every request we resolve the host and require at
    least one globally routable IP address. Redirects are followed manually with
    the same check on each hop.
    """
    current = url
    redirects: list[dict[str, Any]] = []
    for _ in range(max_redirects + 1):
        if not _is_safe_http_url(current):
            return {
                "http_checked": True,
                "checked_url": url,
                "final_url": current,
                "ok": False,
                "redirects": redirects,
                "error": "unsafe or non-public redirect target",
            }
        try:
            resp = requests.get(current, headers=headers, allow_redirects=False, timeout=timeout, stream=True)
            if resp.is_redirect:
                location = resp.headers.get("Location", "")
                if not location:
                    return {
                        "http_checked": True,
                        "checked_url": url,
                        "final_url": current,
                        "ok": False,
                        "status_code": resp.status_code,
                        "redirects": redirects,
                        "error": "redirect without Location header",
                    }
                next_url = urljoin(current, location)
                redirects.append({"from": current, "to": next_url, "status_code": resp.status_code})
                current = next_url
                continue

            body = resp.raw.read(192_000, decode_content=True)
            text = body.decode(resp.encoding or "utf-8", errors="ignore")
            return {
                "http_checked": True,
                "checked_url": url,
                "ok": bool(resp.ok),
                "status_code": resp.status_code,
                "final_url": resp.url,
                "redirects": redirects,
                "content_type": resp.headers.get("Content-Type", "")[:120],
                "server": resp.headers.get("Server", "")[:120],
                "title": _extract_title(text),
            }
        except requests.RequestException as exc:
            return {
                "http_checked": True,
                "checked_url": url,
                "final_url": current,
                "ok": False,
                "redirects": redirects,
                "error": f"{type(exc).__name__}: {exc}",
            }
    return {
        "http_checked": True,
        "checked_url": url,
        "final_url": current,
        "ok": False,
        "redirects": redirects,
        "error": "too many redirects",
    }


def _is_safe_http_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False
    if not parsed.hostname:
        return False
    return bool(_resolve_public_addresses(parsed.hostname))


def _extract_title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.I | re.S)
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:160]
