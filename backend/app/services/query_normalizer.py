from __future__ import annotations

import re
from dataclasses import dataclass

from app.models import Entity
from app.services.entity_extractor import DOMAIN_RE, EMAIL_RE, IP_RE, URL_RE, extract_entities


DEFAULT_LAUNCH_SUFFIX = (
    "신규 결제 서비스 출시 전 유출 계정, 감염 단말, 랜섬웨어 언급, "
    "텔레그램 위협 신호를 조사하고 Go/No-Go 판단과 72시간 액션 플랜을 만들어줘."
)

_MISSION_WORDS = [
    "출시", "런칭", "launch", "release", "go-live", "golive", "서비스 오픈",
    "m&a", "인수", "합병", "투자", "실사", "due diligence",
    "벤더", "협력사", "공급망", "계약", "vendor", "supplier", "onboarding", "연동",
    "고객", "trust", "신뢰", "보안 질의", "보안문의", "customer",
    "ipo", "감사", "공시", "발표", "이사회", "executive", "board",
    "침해", "incident", "사고", "breach", "랜섬웨어 주장", "claim",
]

_THREAT_WORDS = [
    "계정", "credential", "creds", "id/pw", "password", "비밀번호", "유출",
    "감염", "단말", "stealer", "스틸러", "host", "hostname", "브라우저", "세션",
    "랜섬웨어", "ransom", "ransomware", "협박", "피해 공개",
    "텔레그램", "telegram", "채널", "거래 채널",
    "다크웹", "외부 노출", "위협 신호", "osint", "go/no-go", "no-go", "액션 플랜",
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
    """Turn a bare site address into a full business-moment mission.

    Atlas Lens should be usable by an operator who only knows the target site.
    If the user enters only `google.com` or `https://foo.example`, we preserve the
    concrete target and apply the default product-launch risk gate. If the user
    already supplied a business event or threat intent, the query is left intact.
    """
    original = query.strip()
    entities = extract_entities(original)
    target = _primary_target(entities)
    if not target:
        return NormalizedQuery(original, original, False, False, "")

    if _needs_default_mission(original):
        expanded = f"{target} {DEFAULT_LAUNCH_SUFFIX}"
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
    ql = q.lower()
    if any(word in ql for word in _MISSION_WORDS):
        return False
    if any(word in ql for word in _THREAT_WORDS):
        return False

    remainder = re.sub(URL_RE, " ", q)
    remainder = re.sub(EMAIL_RE, " ", remainder)
    remainder = re.sub(DOMAIN_RE, " ", remainder)
    remainder = re.sub(IP_RE, " ", remainder)
    tokens = re.findall(r"[A-Za-z가-힣0-9_-]+", remainder)
    meaningful = [t for t in tokens if t.lower() not in _LOW_INFORMATION_WORDS]
    return len(meaningful) == 0
