from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

EntityType = Literal["domain", "email", "ip", "cve", "organization", "keyword", "unknown"]
EvidenceType = Literal[
    "credential_exposure", "combo_exposure", "stealer_exposure", "ransomware_mention",
    "leak_mention", "telegram_mention", "vulnerability_pressure", "public_indicator",
    "negative_evidence", "unknown"
]
Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["confirmed", "high", "medium", "low", "unknown"]
Decision = Literal["GO", "GO_WITH_CONTROLS", "NO_GO"]
MissionType = Literal[
    "joint_training", "operation_support", "defense_supplier", "public_release",
    "incident_claim", "mission_assurance", "general"
]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Entity(BaseModel):
    type: EntityType
    value: str
    display: Optional[str] = None
    confidence: float = 0.8


class InvestigationRequest(BaseModel):
    query: str = Field(..., min_length=2, max_length=2000)
    time_window_days: int = Field(default=180, ge=1, le=3650)
    classification: str = Field(default="UNCLASSIFIED//CTI", max_length=128)
    live: bool = True
    max_results_per_source: int = Field(default=5, ge=1, le=50)
    include_public_feeds: bool = True


class MissionContext(BaseModel):
    mission_type: MissionType = "mission_assurance"
    title: str
    target: str
    deadline: str = "not specified"
    mission_event: str
    decision_question: str
    stakeholders: list[str] = Field(default_factory=list)


class TargetProfile(BaseModel):
    kind: str = "unknown"
    value: str = ""
    display: str = ""
    original_query: str = ""
    normalized_query: str = ""
    query_was_expanded: bool = False
    default_mission_applied: bool = False
    public_surface: dict[str, Any] = Field(default_factory=dict)
    collection_notes: list[str] = Field(default_factory=list)


class DecisionGate(BaseModel):
    decision: Decision
    label: str
    rationale: str
    required_controls: list[str] = Field(default_factory=list)
    blocking_conditions: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)


class DeployabilityProfile(BaseModel):
    deployment_locations: list[str] = Field(default_factory=list)
    security_controls: list[str] = Field(default_factory=list)
    operational_limitations: list[str] = Field(default_factory=list)
    integration_points: list[str] = Field(default_factory=list)
    approval_notes: list[str] = Field(default_factory=list)


class AttackMapping(BaseModel):
    framework: str = "MITRE ATT&CK Enterprise"
    tactic: str
    technique_id: str
    technique_name: str
    rationale: str
    evidence_ids: list[str] = Field(default_factory=list)
    confidence: float = 0.5


class StandardsInterop(BaseModel):
    attack_mappings: list[AttackMapping] = Field(default_factory=list)
    stix_bundle: dict[str, Any] = Field(default_factory=dict)
    taxii_readiness: list[str] = Field(default_factory=list)
    references: list[dict[str, str]] = Field(default_factory=list)


class ActionItem(BaseModel):
    id: str
    window: str
    owner: str
    action: str
    success_criteria: str
    evidence_ids: list[str] = Field(default_factory=list)
    status: Literal["required", "recommended", "watch"] = "required"


class InvestigationPlanStep(BaseModel):
    id: str
    module: str
    objective: str
    query: str
    status: Literal["planned", "running", "completed", "skipped", "failed"] = "planned"
    reason: str = ""


class Evidence(BaseModel):
    id: str
    source: str
    module: str
    evidence_type: EvidenceType = "unknown"
    title: str
    summary: str
    entity_refs: list[str] = Field(default_factory=list)
    query: str = ""
    retrieved_at: str = Field(default_factory=now_iso)
    event_time: Optional[str] = None
    confidence: float = 0.5
    severity: Severity = "info"
    citation: str
    raw_ref: Optional[str] = None
    redacted: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class ScoreBreakdown(BaseModel):
    label: str
    score: float
    weight: float
    explanation: str
    evidence_ids: list[str] = Field(default_factory=list)


class RiskModel(BaseModel):
    risk_score: int
    confidence_score: int
    level: Severity
    posture: str
    breakdown: list[ScoreBreakdown]
    assumptions: list[str] = Field(default_factory=list)


class ExposureDNA(BaseModel):
    primary: str
    secondary: list[str]
    vector: dict[str, float]
    interpretation: str
    recommended_posture: str


class ThreatInterpretation(BaseModel):
    externally_observable: list[str]
    likely_assumptions: list[str]
    likely_next_interest: list[str]
    uncertainty: list[str]


class NextBestQuestion(BaseModel):
    question: str
    why_it_matters: str
    data_owner: str
    suggested_log_source: str
    evidence_ids: list[str]
    priority: int


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    score: float = 0.5
    group: str = "default"
    description: str = ""


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    weight: float = 1.0
    evidence_ids: list[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    id: str
    title: str
    time: str
    severity: Severity
    source: str
    summary: str
    evidence_ids: list[str]


class Report(BaseModel):
    executive_summary: str
    key_findings: list[str]
    recommended_actions: list[str]
    caveats: list[str]


class InvestigationResult(BaseModel):
    investigation_id: str
    product: str = "Atlas Lens"
    tagline: str = "Mission exposure intelligence and decision support"
    classification: str
    created_at: str = Field(default_factory=now_iso)
    query: str
    entities: list[Entity]
    mission_context: MissionContext
    target_profile: TargetProfile
    decision_gate: DecisionGate
    deployability: DeployabilityProfile
    standards: StandardsInterop
    action_board: list[ActionItem]
    plan: list[InvestigationPlanStep]
    evidence: list[Evidence]
    risk: RiskModel
    exposure_dna: ExposureDNA
    next_best_questions: list[NextBestQuestion]
    graph: dict[str, list[Any]]
    timeline: list[TimelineEvent]
    report: Report
    safety: dict[str, Any]
