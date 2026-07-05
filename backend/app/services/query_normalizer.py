from __future__ import annotations

import re
from dataclasses import dataclass

from app.models import Entity
from app.services.entity_extractor import DOMAIN_RE, EMAIL_RE, IP_RE, URL_RE, extract_entities


DEFAULT_MISSION_SUFFIX = (
    "연합훈련 전 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 "
    "GO/NO-GO 판단과 72시간 조치 계획을 만들어줘."
)

_MISSION_WORDS = [
    "연합훈련", "훈련", "작전", "임무", "mission", "exercise", "operation", "opsec",
    "지휘통제", "c2", "포털", "공개", "대외발표", "발표", "배포", "개통",
    "방산", "방산망", "협력사", "공급망", "계약", "vendor", "supplier", "onboarding", "연동",
    "감사", "보고", "상황보고", "commander", "command", "brief",
    "침해", "incident", "사고", "breach", "랜섬웨어 주장", "claim",
]

_THREAT_WORDS = [
    "계정", "credential", "creds", "id/pw", "password", "비밀번호", "유출",
    "감염", "단말", "stealer", "스틸러", "host", "hostname", "브라우저", "세션",
    "랜섬웨어", "ransom", "ransomware", "협박", "피해 공개",
    "텔레그램", "telegram", "채널", "거래 채널",
    "다크웹", "외부 노출", "위협 신호", "osint", "go/no-go", "no-go", "액션 플랜",
    "조치 계획", "mission go", "임무 진행", "진행 가능",
]

_LOW_INFORMATION_WORDS = {
    "관련", "대해", "대한", "조사", "조사해줘", "확인", "확인해줘", "검색",
    "검색해줘", "분석", "분석해줘", "알려줘", "점검", "점검해줘", "봐줘",
    "해주세요", "해줘", "사이트", "사이트주소", "주소", "도메인",
}


@dataclass(frozen=True)
class NormalizedQuery:
    original_query: str
    query: str
    query_was_expanded: bool
    default_mission_applied: bool
    target_display: str


def normalize_query(query: str) -> NormalizedQuery:
    """Turn a bare site address into a full mission-assurance query.

    Atlas Lens should be usable by an operator who only knows the target site.
    If the user enters only `defense-supplier.co.kr` or `https://c2-training.example.mil`, we preserve the
    concrete target and apply the default joint-training mission gate. If the user
    already supplied mission context or threat intent, the query is left intact.
    """
    original = query.strip()
    entities = extract_entities(original)
    target = _primary_target(entities)
    if not target:
        return NormalizedQuery(original, original, False, False, "")

    if _needs_default_mission(original):
        expanded = f"{target} {DEFAULT_MISSION_SUFFIX}"
        return NormalizedQuery(original, expanded, True, True, target)

    return NormalizedQuery(original, original, False, False, target)


def _primary_target(entities: list[Entity]) -> str:
    for typ in ("domain", "email", "ip"):
        ent = next((e for e in entities if e.type == typ), None)
        if ent:
            return ent.display or ent.value
    return ""


def _needs_default_mission(query: str) -> bool:
    q = query.strip()
    if not q:
        return False

    remainder = re.sub(URL_RE, " ", q)
    remainder = re.sub(EMAIL_RE, " ", remainder)
    remainder = re.sub(DOMAIN_RE, " ", remainder)
    remainder = re.sub(IP_RE, " ", remainder)
    intent_text = remainder.lower()
    if any(word in intent_text for word in _MISSION_WORDS):
        return False
    if any(word in intent_text for word in _THREAT_WORDS):
        return False

    tokens = re.findall(r"[A-Za-z가-힣0-9_-]+", remainder)
    meaningful = [t for t in tokens if t.lower() not in _LOW_INFORMATION_WORDS]
    return len(meaningful) == 0
