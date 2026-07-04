from __future__ import annotations

import re
import uuid
from collections import Counter
from typing import Any

from app.core.security import safety_classification, stable_hash
from app.models import (
    ActionItem, DecisionGate, Entity, Evidence,
    ExposureDNA, GraphEdge, GraphNode, InvestigationPlanStep, InvestigationRequest, InvestigationResult,
    MissionContext, NextBestQuestion, Report, RiskModel, ScoreBreakdown, TargetProfile,
    ThreatInterpretation, TimelineEvent,
)


ACTIONABLE_EVIDENCE_TYPES = {
    "credential_exposure",
    "combo_exposure",
    "stealer_exposure",
    "ransomware_mention",
    "leak_mention",
    "telegram_mention",
    "vulnerability_pressure",
}


def actionable_evidence(evidence: list[Evidence]) -> list[Evidence]:
    return [ev for ev in evidence if ev.evidence_type in ACTIONABLE_EVIDENCE_TYPES]


def evidence_counts(evidence: list[Evidence], *, actionable_only: bool = True) -> Counter:
    if actionable_only:
        evidence = actionable_evidence(evidence)
    return Counter(ev.evidence_type for ev in evidence)


def level_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    if score >= 20:
        return "low"
    return "info"


def subject_label(entities: list[Entity]) -> str:
    return next((e.display or e.value for e in entities if e.type in ["domain", "organization", "email", "ip"]), "Investigation Subject")


def build_mission_context(req: InvestigationRequest, entities: list[Entity]) -> MissionContext:
    q = req.query.lower()
    target = subject_label(entities)
    if any(x in q for x in ["출시", "런칭", "launch", "release", "go-live", "golive", "서비스 오픈"]):
        mission_type = "product_launch"
        title = "Product launch risk gate"
        event = "제품 또는 서비스 출시 전 외부 위협 신호 검증"
        question = "현재 외부 노출 신호를 기준으로 출시를 진행해도 되는가?"
        stakeholders = ["Product", "Security", "IAM", "SOC", "Customer Support"]
    elif any(x in q for x in ["m&a", "인수", "합병", "투자", "실사", "due diligence", "acquire"]):
        mission_type = "mna"
        title = "Deal cyber due diligence gate"
        event = "투자·인수·합병 전 외부 노출 리스크 검증"
        question = "거래를 진행하기 전에 보안 조건 또는 가격·계약 조정이 필요한가?"
        stakeholders = ["Corporate Development", "Legal", "Security", "Finance", "Executive"]
    elif any(x in q for x in ["벤더", "협력사", "공급망", "계약", "vendor", "supplier", "onboarding", "연동"]):
        mission_type = "vendor_onboarding"
        title = "Vendor onboarding risk gate"
        event = "신규 벤더·협력사·외부 연동 전 위협 노출 검증"
        question = "해당 벤더를 연결해도 되는가, 또는 어떤 통제를 계약 조건으로 넣어야 하는가?"
        stakeholders = ["Vendor Risk", "Procurement", "Security", "Legal", "Service Owner"]
    elif any(x in q for x in ["고객", "trust", "신뢰", "보안 질의", "보안문의", "customer"]):
        mission_type = "customer_trust"
        title = "Customer trust response gate"
        event = "고객 보안 질의 또는 신뢰 대응 전 외부 노출 검증"
        question = "고객에게 공유 가능한 범위와 내부 보완 조치는 무엇인가?"
        stakeholders = ["Trust", "Security", "Customer Success", "Sales Engineering", "Legal"]
    elif any(x in q for x in ["ipo", "감사", "공시", "발표", "이사회", "executive", "board"]):
        mission_type = "executive_event"
        title = "Executive event risk gate"
        event = "공시·감사·이사회·대외 발표 전 외부 위협 신호 검증"
        question = "대외 일정 전에 보안 리스크를 경영진에게 어떻게 보고해야 하는가?"
        stakeholders = ["Executive", "Security", "Legal", "PR", "Compliance"]
    elif any(x in q for x in ["침해", "incident", "사고", "breach", "랜섬웨어 주장", "claim"]):
        mission_type = "incident_precheck"
        title = "Incident pre-check gate"
        event = "침해 의심 또는 외부 주장 검증"
        question = "외부 주장이 내부 사고 대응으로 승격될 만큼 근거가 충분한가?"
        stakeholders = ["SOC", "IR", "Security", "Legal", "PR"]
    else:
        mission_type = "general"
        title = "Business-moment risk gate"
        event = "중요 업무 결정 전 외부 위협 신호 검증"
        question = "현재 외부 노출 신호가 이 업무 결정을 지연시키거나 조건부 진행하게 만드는가?"
        stakeholders = ["Security", "SOC", "Business Owner", "IAM"]

    deadline = _infer_deadline(req.query)
    return MissionContext(
        mission_type=mission_type,
        title=title,
        target=target,
        deadline=deadline,
        business_event=event,
        decision_question=question,
        stakeholders=stakeholders,
    )


def _infer_deadline(query: str) -> str:
    patterns = [
        r"(오늘|내일|이번 주|다음 주|금요일|월요일|화요일|수요일|목요일|토요일|일요일)",
        r"(\d{4}[-./]\d{1,2}[-./]\d{1,2})",
        r"(\d{1,2}월\s*\d{1,2}일)",
        r"(T[-+]\s*\d{1,3}\s*h)",
    ]
    for pat in patterns:
        m = re.search(pat, query, re.I)
        if m:
            return m.group(1)
    return "not specified"


def build_risk(evidence: list[Evidence]) -> RiskModel:
    risk_ev = actionable_evidence(evidence)
    c = evidence_counts(risk_ev)
    breakdown: list[ScoreBreakdown] = []

    def add(label: str, score: float, weight: float, explanation: str, types: list[str]) -> None:
        ids = [ev.id for ev in risk_ev if ev.evidence_type in types]
        breakdown.append(ScoreBreakdown(label=label, score=score, weight=weight, explanation=explanation, evidence_ids=ids[:6]))

    credential = min(1.0, (c["credential_exposure"] + c["combo_exposure"] * 0.8) / 3)
    stealer = min(1.0, c["stealer_exposure"] / 2)
    actor = min(1.0, (c["ransomware_mention"] + c["leak_mention"] + c["telegram_mention"] * 0.7) / 4)
    freshness = 0.65 if risk_ev else 0.05
    cross = min(1.0, len({ev.module for ev in risk_ev}) / 5)

    add("Credential exposure pressure", credential, 0.24, "유출 계정과 combo 노출은 로그인 기반 초기 접근 가능성을 높입니다.", ["credential_exposure", "combo_exposure"])
    add("Stealer endpoint pressure", stealer, 0.28, "감염 단말 흔적은 세션·브라우저 credential 노출 가능성을 시사합니다.", ["stealer_exposure"])
    add("Threat ecosystem proximity", actor, 0.20, "랜섬웨어·유출·텔레그램 언급은 외부 위협 생태계와의 인접성을 나타냅니다.", ["ransomware_mention", "leak_mention", "telegram_mention"])
    add("Freshness", freshness, 0.12, "최근 관측 신호일수록 이벤트 전 조치 우선순위가 높습니다.", [ev.evidence_type for ev in evidence])
    add("Cross-source corroboration", cross, 0.16, "서로 다른 모듈에서 교차 확인될수록 의사결정 신뢰도가 증가합니다.", [ev.evidence_type for ev in evidence])

    score = int(sum(x.score * x.weight for x in breakdown) * 100)
    confidence = int(min(0.95, 0.25 + cross * 0.55 + min(len(risk_ev), 8) * 0.025) * 100)
    posture = "Decision-ready watch" if score < 45 else "Conditional control required"
    if stealer > 0.4:
        posture = "Endpoint-first pre-event containment"
    if score >= 70:
        posture = "Event gate escalation"
    return RiskModel(
        risk_score=score, confidence_score=confidence, level=level_from_score(score), posture=posture,
        breakdown=breakdown,
        assumptions=[
            "외부 OSINT 신호는 내부 침해를 직접 입증하지 않으며, IAM/EDR/SIEM 로그로 검증해야 합니다.",
            "GO/NO-GO 판단은 기술 evidence와 비즈니스 중요도를 함께 고려한 운영 권고입니다.",
        ],
    )


def build_decision_gate(mission: MissionContext, risk: RiskModel, evidence: list[Evidence]) -> DecisionGate:
    risk_ev = actionable_evidence(evidence)
    c = evidence_counts(risk_ev)
    ids = [ev.id for ev in risk_ev[:8]]
    has_stealer = c["stealer_exposure"] > 0
    has_actor = c["ransomware_mention"] + c["leak_mention"] + c["telegram_mention"] > 0
    has_cred = c["credential_exposure"] + c["combo_exposure"] > 0

    if risk.risk_score >= 75 or (has_stealer and has_actor):
        decision = "NO_GO"
        label = "NO-GO"
        rationale = f"{mission.target}에서 감염 단말 또는 위협 생태계 신호가 교차되어, 현재 상태로는 {mission.business_event} 진행 전 추가 검증과 차단 조치가 필요합니다."
        blocking = [
            "감염 단말 또는 계정 탈취 정황이 내부 자산과 연결되는지 확인되지 않음",
            "출시·계약·대외 발표 전에 세션 폐기와 계정 조치 완료 여부가 확인되지 않음",
        ]
    elif risk_ev:
        decision = "GO_WITH_CONTROLS"
        label = "GO WITH CONTROLS"
        rationale = f"{mission.target} 관련 외부 노출 evidence가 확인되었습니다. 이벤트 자체를 즉시 중단할 수준으로 단정할 수는 없지만, 조건부 통제와 72시간 모니터링을 전제로 진행해야 합니다."
        blocking = ["필수 IAM/EDR/SOC 확인 항목이 마감 전 완료되지 않을 경우 NO-GO로 재평가"]
    else:
        decision = "GO"
        label = "GO"
        rationale = f"현재 조회 범위에서 {mission.target}에 대한 정규화된 외부 노출 evidence는 확인되지 않았습니다. 단, 외부 신호 부재는 침해 부재를 입증하지 않으므로 기본 로그 검증을 조건으로 진행 가능합니다."
        blocking = ["내부 인증 로그 또는 EDR에서 별도 이상 징후가 확인될 경우 재평가"]

    controls: list[str] = []
    if has_cred:
        controls.append("유출 계정 후보의 비밀번호 재설정, MFA 상태 확인, SSO/VPN 세션 폐기")
    if has_stealer:
        controls.append("감염 단말 후보의 EDR/MDM/CMDB 매칭과 브라우저 저장 credential 정책 점검")
    if has_actor:
        controls.append("랜섬웨어·유출·텔레그램 watch 키워드 등록과 72시간 SOC 모니터링")
    if not controls:
        controls.extend([
            "이벤트 전 24시간 SSO/VPN/메일 로그인 이상 징후 확인",
            "대상 도메인과 주요 계정에 대한 watch query 유지",
        ])
    controls.append("증거와 조치 결과를 executive brief로 기록")
    return DecisionGate(decision=decision, label=label, rationale=rationale, required_controls=controls, blocking_conditions=blocking, evidence_ids=ids)


def build_action_board(mission: MissionContext, evidence: list[Evidence], gate: DecisionGate) -> list[ActionItem]:
    c = evidence_counts(evidence)
    ids_cred = [ev.id for ev in evidence if ev.evidence_type in ["credential_exposure", "combo_exposure"]][:5]
    ids_stealer = [ev.id for ev in evidence if ev.evidence_type == "stealer_exposure"][:5]
    ids_actor = [ev.id for ev in evidence if ev.evidence_type in ["ransomware_mention", "leak_mention", "telegram_mention"]][:5]
    items: list[ActionItem] = []

    def add(window: str, owner: str, action: str, success: str, evidence_ids: list[str], status: str = "required") -> None:
        items.append(ActionItem(id=f"A{len(items)+1}", window=window, owner=owner, action=action, success_criteria=success, evidence_ids=evidence_ids, status=status))

    if c["credential_exposure"] or c["combo_exposure"]:
        add("T-72h", "IAM", "노출 계정 후보의 현재 재직·권한·최근 로그인 여부를 확인하고 필요한 계정은 비밀번호 재설정과 세션 폐기를 수행", "유출 후보 계정 목록별 owner, 조치 상태, 남은 예외가 기록됨", ids_cred)
    else:
        add("T-72h", "IAM", "대상 도메인의 핵심 관리자·고객지원 계정에 대해 MFA, 신규 국가 로그인, 세션 재발급 이벤트를 점검", "이벤트 전 계정 이상 징후가 없거나 예외가 승인됨", [])

    if c["stealer_exposure"]:
        add("T-48h", "Endpoint", "스틸러 로그의 username, hostname, IP를 EDR/MDM/CMDB와 대조하고 감염 가능 단말을 격리 또는 재점검", "매칭된 자산의 감염 여부와 containment 상태가 확인됨", ids_stealer)
    else:
        add("T-48h", "SOC", "대상 도메인과 주요 로그인 포털에 대한 credential stuffing, impossible travel, 신규 ASN 룰을 점검", "탐지 룰이 활성화되어 이벤트 기간 동안 알림이 수집됨", [], "recommended")

    if c["ransomware_mention"] or c["leak_mention"] or c["telegram_mention"]:
        add("T-24h", "SOC", "랜섬웨어·유출·텔레그램 키워드를 watchlist에 등록하고 반복 언급 또는 판매 정황을 모니터링", "watch query와 담당자가 지정되고 재언급 시 escalation 경로가 정의됨", ids_actor)
    else:
        add("T-24h", "Security", "외부 CTI 재조회와 내부 SIEM quick sweep를 수행해 신규 evidence 발생 여부를 확인", "마감 전 최종 check 결과가 decision gate에 반영됨", [], "watch")

    add("T-4h", "Business Owner", f"{mission.title} 결과를 기준으로 {gate.label} 결정을 승인하거나 예외를 문서화", "진행 여부, 조건, 잔여 리스크 owner가 명시됨", gate.evidence_ids, "required")
    add("T+24h", "SOC", "이벤트 이후 신규 로그인, 고객지원 계정 사용, 외부 언급 재등장을 모니터링하고 brief를 갱신", "사후 24시간 관측 결과와 후속 조치가 기록됨", gate.evidence_ids, "watch")
    return items


def build_exposure_dna(evidence: list[Evidence]) -> ExposureDNA:
    risk_ev = actionable_evidence(evidence)
    c = evidence_counts(risk_ev)
    vector = {
        "credential": min(100, (c["credential_exposure"] + c["combo_exposure"]) * 28),
        "stealer": min(100, c["stealer_exposure"] * 42),
        "ransomware_adjacent": min(100, c["ransomware_mention"] * 50),
        "leak_chatter": min(100, c["leak_mention"] * 35),
        "telegram_chatter": min(100, c["telegram_mention"] * 35),
        "corroboration": min(100, len({ev.module for ev in risk_ev}) * 18),
    }
    primary = max(vector.items(), key=lambda kv: kv[1])[0] if risk_ev else "insufficient-data"
    labels = {
        "credential": "Credential-heavy",
        "stealer": "Stealer-infected",
        "ransomware_adjacent": "Ransomware-adjacent",
        "leak_chatter": "Leak-chatter-exposed",
        "telegram_chatter": "Telegram-mentioned",
        "corroboration": "Cross-source-corroborated",
        "insufficient-data": "Insufficient external signal",
    }
    secondary = [labels[k] for k, v in sorted(vector.items(), key=lambda kv: kv[1], reverse=True)[1:4] if v > 0]
    if primary == "stealer":
        interp = "노출 양상은 감염 단말 기반 정보 유출에 가깝습니다. 이벤트 전 단말 검증과 세션 폐기가 우선입니다."
        posture = "Endpoint-first event gate"
    elif primary == "credential":
        interp = "노출 양상은 계정 재사용과 credential stuffing 위험이 중심입니다. IAM 조치를 진행 조건으로 두는 것이 합리적입니다."
        posture = "Identity-first event gate"
    elif primary == "ransomware_adjacent":
        interp = "랜섬웨어 생태계와의 인접 신호가 확인됩니다. 대외 발표나 계약 전 escalation 기준이 필요합니다."
        posture = "Crisis-watch event gate"
    else:
        interp = "외부 노출 신호가 제한적이거나 분산되어 있어 기본 내부 로그 검증과 watch 유지가 중요합니다."
        posture = "Evidence-building event gate"
    return ExposureDNA(primary=labels.get(primary, primary), secondary=secondary, vector=vector, interpretation=interp, recommended_posture=posture)


def build_threat_interpretation(entities: list[Entity], evidence: list[Evidence]) -> ThreatInterpretation:
    c = evidence_counts(evidence)
    known = []
    assumptions = []
    interests = []
    uncertainty = []
    if c["credential_exposure"] or c["combo_exposure"]:
        known.append("도메인 또는 계정 패턴이 외부 credential 데이터에 노출되어 있을 수 있습니다.")
        assumptions.append("공격자는 VPN/SSO/메일 계정 재사용 가능성을 가정할 수 있습니다.")
        interests.append("인증 포털, MFA 흐름, 임직원 이메일 패턴")
    if c["stealer_exposure"]:
        known.append("stealer 감염 단말 기반의 host/user 흔적이 공격자에게 유용한 정찰 단서가 될 수 있습니다.")
        assumptions.append("공격자는 저장 세션, 브라우저 credential, 업무용 단말명을 단서로 삼을 수 있습니다.")
        interests.append("원격접속·메일·협업도구 세션, 단말명 기반 내부 피싱")
    if c["ransomware_mention"] or c["leak_mention"]:
        known.append("동일 조직 또는 인접 산업군의 유출·협박 언급이 관측됩니다.")
        assumptions.append("공격자는 공급망·협력사 경로가 우회 접근 지점이라고 판단할 수 있습니다.")
        interests.append("협력사 포털, 자료 교환 채널, 백업·파일서버 노출면")
    if c["telegram_mention"]:
        known.append("텔레그램 기반 위협 채널에서 낮거나 중간 신뢰도의 언급이 존재합니다.")
        assumptions.append("공격자는 공개/반공개 거래 채널에서 계정이나 접근권한을 탐색할 수 있습니다.")
        interests.append("키워드 watch, 가짜 거래 유도 금지, 방어형 조기경보")
    if not known:
        known.append("현재 조회 범위에서는 강한 외부 노출 신호가 제한적입니다.")
        uncertainty.append("도메인, 이메일, 벤더명, 이벤트 유형을 보강하면 분석 신뢰도가 올라갑니다.")
    uncertainty.extend([
        "내부 인증 로그와 자산 CMDB가 없으면 실제 접근 성공 여부는 확인할 수 없습니다.",
        "외부 데이터의 시점·정확도는 공급원별 편차가 있어 analyst review가 필요합니다.",
    ])
    return ThreatInterpretation(externally_observable=known, likely_assumptions=assumptions, likely_next_interest=interests, uncertainty=uncertainty)


def build_next_questions(evidence: list[Evidence]) -> list[NextBestQuestion]:
    ids_cred = [ev.id for ev in evidence if ev.evidence_type in ["credential_exposure", "combo_exposure"]][:4]
    ids_stealer = [ev.id for ev in evidence if ev.evidence_type == "stealer_exposure"][:4]
    ids_actor = [ev.id for ev in evidence if ev.evidence_type in ["ransomware_mention", "leak_mention", "telegram_mention"]][:4]
    return [
        NextBestQuestion(question="유출 계정이 최근 30일 내 VPN/SSO/Mail에 성공 로그인했는가?", why_it_matters="외부 유출 신호가 실제 초기 접근으로 전환되었는지 확인하는 가장 직접적인 질문입니다.", data_owner="IAM/SOC", suggested_log_source="SSO, VPN, IdP, Mail audit logs", evidence_ids=ids_cred, priority=1),
        NextBestQuestion(question="감염 단말 흔적의 username/hostname이 실제 사내 자산과 일치하는가?", why_it_matters="CDS 신호가 조직 내부 단말과 연결되는지 검증해야 합니다.", data_owner="Endpoint/CMDB", suggested_log_source="EDR, MDM, CMDB, asset inventory", evidence_ids=ids_stealer, priority=2),
        NextBestQuestion(question="유출 시점 이후 MFA 재등록, 세션 재발급, 신규 국가 로그인 이벤트가 있었는가?", why_it_matters="계정 탈취 후 안정적 접근 확보 시도를 구분할 수 있습니다.", data_owner="IAM/SOC", suggested_log_source="IdP MFA logs, session logs", evidence_ids=ids_cred + ids_stealer, priority=3),
        NextBestQuestion(question="동일 산업군 또는 협력사에서 유사한 랜섬웨어·유출 언급이 증가하고 있는가?", why_it_matters="직접 피해가 없어도 공급망·인접 산업군 압력을 평가할 수 있습니다.", data_owner="CTI/SOC", suggested_log_source="RM/LM/TT watchlist, vendor risk feed", evidence_ids=ids_actor, priority=4),
    ]


def build_graph(mission: MissionContext, entities: list[Entity], evidence: list[Evidence], actions: list[ActionItem]) -> dict[str, list[Any]]:
    nodes: list[GraphNode] = []
    edges: list[GraphEdge] = []
    mission_id = "mission:event"
    target_id = "target:subject"
    nodes.append(GraphNode(id=mission_id, label=mission.title, type="business_event", score=1, group="mission", description=mission.business_event))
    nodes.append(GraphNode(id=target_id, label=mission.target, type="target", score=1, group="subject", description="조사 대상"))
    edges.append(GraphEdge(id="M-target", source=mission_id, target=target_id, label="assesses", weight=1, evidence_ids=[]))

    type_nodes = {
        "public_indicator": ("surface:public", "Public surface", "subject", "대상 도메인의 공개 DNS/HTTP 표면"),
        "credential_exposure": ("exposure:credential", "Credential exposure", "exposure", "로그인 기반 초기 접근 기회"),
        "combo_exposure": ("exposure:combo", "Combo reuse", "exposure", "계정 재사용 가능성"),
        "stealer_exposure": ("exposure:stealer", "Stealer endpoint", "exposure", "세션·단말 단서 기반 공격 기회"),
        "ransomware_mention": ("threat:ransomware", "Ransomware proximity", "impact", "대외 리스크와 위기 커뮤니케이션 압력"),
        "leak_mention": ("threat:leak", "Leak chatter", "impact", "유출·협박 언급 기반 비즈니스 영향"),
        "telegram_mention": ("threat:telegram", "Telegram chatter", "impact", "거래 채널 기반 조기 경보 신호"),
    }
    created = {mission_id, target_id}
    for ev in evidence:
        if ev.evidence_type in type_nodes:
            nid, lbl, group, desc = type_nodes[ev.evidence_type]
            if nid not in created:
                nodes.append(GraphNode(id=nid, label=lbl, type=ev.evidence_type, score=ev.confidence, group=group, description=desc))
                created.add(nid)
            edges.append(GraphEdge(id=f"EV-{ev.id}", source=target_id, target=nid, label=ev.module, weight=max(0.4, ev.confidence), evidence_ids=[ev.id]))
    for action in actions[:5]:
        nid = f"action:{action.id}"
        nodes.append(GraphNode(id=nid, label=f"{action.owner}: {action.window}", type="control", score=0.75, group="control", description=action.action))
        linked = False
        for evid in action.evidence_ids[:3]:
            ev = next((x for x in evidence if x.id == evid), None)
            if ev and ev.evidence_type in type_nodes:
                edges.append(GraphEdge(id=f"AC-{action.id}-{evid}", source=type_nodes[ev.evidence_type][0], target=nid, label="requires", weight=0.8, evidence_ids=[evid]))
                linked = True
        if not linked:
            edges.append(GraphEdge(id=f"AC-{action.id}-mission", source=target_id, target=nid, label="baseline control", weight=0.4, evidence_ids=[]))
    return {"nodes": [n.model_dump() for n in nodes], "edges": [e.model_dump() for e in edges]}


def build_timeline(evidence: list[Evidence]) -> list[TimelineEvent]:
    out = []
    for ev in evidence:
        if ev.event_time:
            out.append(TimelineEvent(id=f"T-{ev.id}", title=ev.title, time=ev.event_time, severity=ev.severity, source=ev.source, summary=ev.summary, evidence_ids=[ev.id]))
    return sorted(out, key=lambda x: x.time, reverse=True)[:12]


def build_report(
    mission: MissionContext,
    gate: DecisionGate,
    risk: RiskModel,
    dna: ExposureDNA,
    interpretation: ThreatInterpretation,
    actions: list[ActionItem],
    evidence: list[Evidence],
    target_profile: TargetProfile,
) -> Report:
    key_findings: list[str] = []
    risk_ev = actionable_evidence(evidence)
    public_ev = [ev for ev in evidence if ev.evidence_type == "public_indicator"]
    if risk_ev:
        key_findings.append(f"총 {len(risk_ev)}개의 외부 노출/위협 신호가 정규화되었고, {len({e.module for e in risk_ev})}개 CTI 모듈에서 근거가 수집되었습니다.")
    else:
        key_findings.append("현재 조회 범위에서는 정규화된 외부 노출 evidence가 확인되지 않았습니다.")
    if public_ev:
        surface = target_profile.public_surface or {}
        key_findings.append(
            f"대상 사이트 context: {target_profile.display} → {surface.get('final_url') or surface.get('checked_url') or '웹 표면 미확인'}, "
            f"HTTP {surface.get('status_code', 'unknown')}, public IP {surface.get('resolved_address_count', 0)}개."
        )
    if target_profile.query_was_expanded:
        key_findings.append("사이트 주소만 입력되어 기본 '신규 결제 서비스 출시 전' decision gate로 자동 확장했습니다.")
    key_findings.append(f"Decision Gate는 {gate.label}이며, Risk Score는 {risk.risk_score}, Confidence Score는 {risk.confidence_score}입니다.")
    key_findings.append(f"Exposure DNA는 {dna.primary} 유형이며, 권장 자세는 {dna.recommended_posture}입니다.")
    for item in interpretation.externally_observable[:2]:
        key_findings.append(item)

    recommended = [f"{a.window} · {a.owner}: {a.action}" for a in actions[:5]]
    summary = f"Atlas Lens는 {mission.target}의 {mission.business_event}에 대해 {gate.label} 결정을 권고합니다. {gate.rationale}"
    caveats = [
        "외부 OSINT는 내부 침해 성공을 입증하지 않습니다. 내부 IAM/EDR/SIEM 로그 검증이 필요합니다.",
        "이 결정은 현재 조회 범위와 API 응답을 기준으로 한 운영 권고이며, 비즈니스 owner의 예외 승인 절차가 필요할 수 있습니다.",
    ]
    return Report(executive_summary=summary, key_findings=key_findings, recommended_actions=recommended, caveats=caveats)


def assemble_result(
    req: InvestigationRequest,
    entities: list[Entity],
    plan_steps: list[InvestigationPlanStep],
    evidence: list[Evidence],
    target_profile: TargetProfile,
) -> InvestigationResult:
    mission = build_mission_context(req, entities)
    risk = build_risk(evidence)
    dna = build_exposure_dna(evidence)
    interpretation = build_threat_interpretation(entities, evidence)
    gate = build_decision_gate(mission, risk, evidence)
    actions = build_action_board(mission, evidence, gate)
    nbq = build_next_questions(evidence)
    graph = build_graph(mission, entities, evidence, actions)
    timeline = build_timeline(evidence)
    report = build_report(mission, gate, risk, dna, interpretation, actions, evidence, target_profile)
    return InvestigationResult(
        investigation_id=stable_hash(str(uuid.uuid4()), prefix="atlas"),
        classification=req.classification,
        query=req.query,
        entities=entities,
        mission_context=mission,
        target_profile=target_profile,
        decision_gate=gate,
        action_board=actions,
        plan=plan_steps,
        evidence=evidence,
        risk=risk,
        exposure_dna=dna,
        next_best_questions=nbq,
        graph=graph,
        timeline=timeline,
        report=report,
        safety=safety_classification(),
    )
