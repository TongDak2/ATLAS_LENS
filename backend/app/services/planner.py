from __future__ import annotations

from app.models import Entity, InvestigationPlanStep


def _has_any(q: str, words: list[str]) -> bool:
    return any(w.lower() in q.lower() for w in words)


def infer_intent(query: str) -> dict[str, bool]:
    q = query.lower()
    credential = _has_any(q, ["계정", "credential", "creds", "id/pw", "password", "비밀번호", "유출 계정", "계정 유출"])
    stealer = _has_any(q, ["감염", "단말", "stealer", "스틸러", "host", "hostname", "브라우저", "세션"])
    ransomware = _has_any(q, ["랜섬웨어", "ransom", "ransomware", "협박", "피해 공개"])
    telegram = _has_any(q, ["텔레그램", "telegram", "채널", "거래 채널"])
    monitoring = _has_any(q, ["기업 유출", "유출 언급", "다크웹", "언급", "osint", "외부 노출", "위협 신호"])
    government = _has_any(q, ["정부", "공공", "기관", "go.kr", ".mil", ".gov"])
    business_gate = _has_any(q, ["go/no-go", "no-go", "액션 플랜", "의사결정", "출시", "계약", "인수", "고객", "벤더", "vendor", "launch", "deal", "trust"])
    broad = _has_any(q, ["전체", "종합", "위협 신호", "분석하고", "생성해줘", "판단"]) or business_gate
    credential_only = credential and not any([stealer, ransomware, telegram, broad, monitoring, government])
    return {
        "credential": credential,
        "stealer": stealer,
        "ransomware": ransomware,
        "telegram": telegram,
        "monitoring": monitoring,
        "government": government,
        "broad": broad,
        "credential_only": credential_only,
    }


def _is_government_or_public_domain(domain: str) -> bool:
    d = domain.lower()
    return d.endswith(".go.kr") or d.endswith(".gov") or ".mil" in d or "mod" in d


def build_plan(entities: list[Entity], max_results: int, query: str = "") -> list[InvestigationPlanStep]:
    primary = next((e for e in entities if e.type in {"domain", "email", "ip", "organization", "keyword"}), entities[0])
    q = primary.value
    intent = infer_intent(query)
    steps: list[InvestigationPlanStep] = []

    def add(module: str, objective: str, query_value: str, reason: str = "") -> None:
        steps.append(InvestigationPlanStep(id=f"P{len(steps)+1}", module=module, objective=objective, query=query_value, reason=reason))

    if primary.type == "domain":
        gov_like = _is_government_or_public_domain(q) or intent["government"]
        # Credential modules are cheap, high-signal first checks for a site/domain.
        if intent["credential"] or intent["broad"] or not query:
            add("CL", "도메인 기반 유출 계정 확인", f"domain:{q}", "Credential Lookout live search")
            add("CB", "ID/PW 조합 재사용 가능성 확인", f"domain:{q}", "Combo Binder live search")
        if intent["stealer"] or intent["broad"]:
            add("CDS", "stealer 감염 단말 기반 계정·호스트 노출 확인", f"domain:{q}", "Compromised Data Set live search")
        if intent["monitoring"] or intent["broad"]:
            add("LM", "기업/산업군 유출·협박 언급 확인", f"domain:{q}", "Leaked Monitoring live search")
        if gov_like and (intent["monitoring"] or intent["broad"]):
            add("GM", "정부·공공 관련 위협 모니터링 확인", f"domain:{q}", "Government Monitoring live search")
        if intent["ransomware"] or intent["broad"]:
            add("RM", "랜섬웨어 공개 피해·인접 피해 흐름 확인", f"domain:{q}", "Ransomware Monitoring live search")
        if intent["telegram"] or intent["broad"]:
            add("TT", "텔레그램 내 도메인·URL·키워드 언급 확인", q, "Telegram Tracker async live search")
        if not steps:
            add("CL", "도메인 기반 유출 계정 확인", f"domain:{q}", "default live account exposure check")
            add("LM", "외부 유출·협박 언급 확인", f"domain:{q}", "default live external exposure check")
    elif primary.type == "email":
        add("CL", "이메일 유출 여부 확인", f"email:{q}", "Credential Lookout live search")
        add("CB", "이메일 기반 combo 노출 확인", f"email:{q}", "Combo Binder live search")
        if intent["stealer"] or intent["broad"]:
            add("CDS", "감염 단말·브라우저 credential 노출 확인", f"email:{q}", "Compromised Data Set live search")
        if intent["telegram"] or intent["broad"]:
            add("TT", "텔레그램 언급 확인", q, "Telegram Tracker async live search")
    elif primary.type == "ip":
        add("CDS", "IP 기반 감염 단말·스틸러 노출 확인", f"ip:{q}", "Compromised Data Set live IP search")
        add("LM", "IP 기반 외부 유출·위협 언급 확인", f"ip:{q}", "Leaked Monitoring live IP search")
        if intent["government"] or intent["broad"]:
            add("GM", "IP 기반 정부·공공 관련 위협 모니터링 확인", f"ip:{q}", "Government Monitoring live IP search")
        if intent["ransomware"] or intent["broad"]:
            add("RM", "IP 기반 랜섬웨어 공개 피해 확인", f"ip:{q}", "Ransomware Monitoring live IP search")
        if intent["telegram"] or intent["broad"]:
            add("TT", "텔레그램 내 IP 언급 확인", f"ip:{q}", "Telegram Tracker async live IP search")
    else:
        add("LM", "키워드 기반 유출·협박 언급 확인", q, "Leaked Monitoring live search")
        if intent["government"] or intent["broad"]:
            add("GM", "정부·공공 관련 위협 모니터링 확인", q, "Government Monitoring live search")
        if intent["ransomware"] or intent["broad"]:
            add("RM", "키워드 기반 랜섬웨어 공개 피해 확인", q, "Ransomware Monitoring live search")
        if intent["telegram"] or intent["broad"]:
            add("TT", "텔레그램 위협 언급 확인", q, "Telegram Tracker async live search")

    cves = [e.value for e in entities if e.type == "cve"]
    for cve in cves:
        add("CISA_KEV", "실제 악용 취약점 카탈로그 확인", cve, "public feed enrichment")
        add("EPSS", "30일 악용 가능성 보강", cve, "public feed enrichment")
    return steps
