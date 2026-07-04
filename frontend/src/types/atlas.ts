export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type Decision = 'GO' | 'GO_WITH_CONTROLS' | 'NO_GO'

export interface Entity { type: string; value: string; display?: string; confidence: number }
export interface MissionContext { mission_type: string; title: string; target: string; deadline: string; business_event: string; decision_question: string; stakeholders: string[] }
export interface TargetProfile {
  kind: string
  value: string
  display: string
  original_query: string
  normalized_query: string
  query_was_expanded: boolean
  default_mission_applied: boolean
  public_surface: Record<string, unknown>
  collection_notes: string[]
}
export interface DecisionGate { decision: Decision; label: string; rationale: string; required_controls: string[]; blocking_conditions: string[]; evidence_ids: string[] }
export interface ActionItem { id: string; window: string; owner: string; action: string; success_criteria: string; evidence_ids: string[]; status: string }
export interface PlanStep { id: string; module: string; objective: string; query: string; status: string; reason: string }
export interface Evidence { id: string; source: string; module: string; evidence_type: string; title: string; summary: string; query: string; retrieved_at: string; event_time?: string; confidence: number; severity: Severity; citation: string; metadata?: Record<string, unknown> }
export interface ScoreBreakdown { label: string; score: number; weight: number; explanation: string; evidence_ids: string[] }
export interface Risk { risk_score: number; confidence_score: number; level: Severity; posture: string; breakdown: ScoreBreakdown[]; assumptions: string[] }
export interface ExposureDNA { primary: string; secondary: string[]; vector: Record<string, number>; interpretation: string; recommended_posture: string }
export interface NextBestQuestion { question: string; why_it_matters: string; data_owner: string; suggested_log_source: string; evidence_ids: string[]; priority: number }
export interface GraphNode { id: string; label: string; type: string; score: number; group: string; description: string }
export interface GraphEdge { id: string; source: string; target: string; label: string; weight: number; evidence_ids: string[] }
export interface TimelineEvent { id: string; title: string; time: string; severity: Severity; source: string; summary: string; evidence_ids: string[] }
export interface Report { executive_summary: string; key_findings: string[]; recommended_actions: string[]; caveats: string[] }
export interface InvestigationResult {
  investigation_id: string
  product: string
  tagline: string
  classification: string
  created_at: string
  query: string
  entities: Entity[]
  mission_context: MissionContext
  target_profile: TargetProfile
  decision_gate: DecisionGate
  action_board: ActionItem[]
  plan: PlanStep[]
  evidence: Evidence[]
  risk: Risk
  exposure_dna: ExposureDNA
  next_best_questions: NextBestQuestion[]
  graph: { nodes: GraphNode[]; edges: GraphEdge[] }
  timeline: TimelineEvent[]
  report: Report
  safety: { mode: string; controls: string[] }
}
