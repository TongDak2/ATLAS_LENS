import React, { useMemo, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { AlertTriangle, ArrowRight, CheckCircle2, Clock, Database, ExternalLink, FileText, GitBranch, Globe2, KeyRound, ListChecks, ShieldCheck, Target } from 'lucide-react'
import { investigate } from './lib/api'
import type { ActionItem, Evidence, GraphEdge, GraphNode, InvestigationResult, Severity } from './types/atlas'
import './styles/global.css'

const exampleQuery = '다음 주 연합훈련 전 defense-supplier.co.kr 관련 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Mission GO/NO-GO 판단과 72시간 조치 계획을 만들어줘.'

type Detail = { kind: 'evidence'; item: Evidence } | { kind: 'action'; item: ActionItem } | null

function fmtDate(s?: string) {
  if (!s) return 'unknown'
  const d = new Date(s)
  return Number.isNaN(d.getTime()) ? s : d.toLocaleString('ko-KR')
}
function rawOf(ev: Evidence): Record<string, unknown> {
  const raw = ev.metadata?.raw
  return raw && typeof raw === 'object' ? raw as Record<string, unknown> : {}
}
function proofUrl(ev: Evidence): string | undefined {
  const raw = rawOf(ev)
  const value = raw.proof_url || raw.url || raw.host
  return typeof value === 'string' && value.startsWith('http') ? value : undefined
}
function hasInvestigableTarget(query: string) {
  const q = query.trim()
  if (!q) return false
  const domain = /(?:https?:\/\/)?(?:www\.)?[a-zA-Z0-9-]{1,63}(?:\.[a-zA-Z0-9-]{1,63})+\.[a-zA-Z]{2,63}/
  const email = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/
  const ip = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/
  return domain.test(q) || email.test(q) || ip.test(q)
}
function severityClass(s: Severity | string) { return `severity ${s}` }
function decisionClass(decision: string) { return `decision ${decision.toLowerCase().replace(/_/g, '-')}` }

function Topbar() {
  return <header className="topbar">
    <div className="brand-block">
      <div className="brand-kicker">Mission Exposure Decision Gate</div>
      <h1>ATLAS LENS</h1>
    </div>
    <div className="topbar-note">Evidence-backed mission assurance for exercises, operations, defense suppliers, public releases, and incident claims.</div>
  </header>
}

function CommandPanel({ onRun, loading }: { onRun: (q: string, apiKey: string) => void; loading: boolean }) {
  const [query, setQuery] = useState('')
  const [apiKey, setApiKey] = useState(() => sessionStorage.getItem('atlas_api_key') || '')
  const [validationMessage, setValidationMessage] = useState('')
  const effectiveQuery = query.trim()

  function submitMission() {
    if (!apiKey.trim()) {
      setValidationMessage('운영 API key가 필요합니다. 서버의 ATLAS_API_KEY와 동일한 값을 입력해 주세요.')
      return
    }
    if (!hasInvestigableTarget(query)) {
      setValidationMessage('조사할 실제 사이트 주소, 도메인, 이메일 또는 IP를 포함해 주세요. 사이트 주소만 입력해도 기본 연합훈련 전 Mission Exposure Gate로 자동 확장됩니다. 예: defense-supplier.co.kr')
      return
    }
    sessionStorage.setItem('atlas_api_key', apiKey.trim())
    setValidationMessage('')
    onRun(effectiveQuery, apiKey.trim())
  }

  return <section className="command-panel">
    <div className="section-index">00</div>
    <div className="command-copy">
      <h2>Ask for mission readiness, not a search.</h2>
      <p>작전, 훈련, 방산 협력사 연동, 대외 공개, 침해 주장 같은 임무 상황을 자연어로 입력하면 Atlas Lens가 CTI 모듈을 오케스트레이션하고 evidence를 Mission GO/NO-GO 판단과 72시간 Mission Assurance Board로 변환합니다.</p>
    </div>
    <div className="command-form">
      <label>Mission query</label>
      <textarea value={query} onChange={e => { setQuery(e.target.value); if (validationMessage) setValidationMessage('') }} placeholder={`ex) ${exampleQuery}`} />
      <label>Operator API key</label>
      <div className="key-row">
        <KeyRound size={18}/>
        <input type="password" value={apiKey} onChange={e => { setApiKey(e.target.value); if (validationMessage) setValidationMessage('') }} placeholder="X-Atlas-API-Key" autoComplete="off" />
      </div>
      {validationMessage && <div className="query-validation"><AlertTriangle size={16}/>{validationMessage}</div>}
      <button className="primary" disabled={loading} onClick={submitMission}>{loading ? '조사 중...' : 'Run mission gate'}</button>
    </div>
  </section>
}

function DecisionGate({ result }: { result: InvestigationResult }) {
  const gate = result.decision_gate
  return <section className="decision-wrap">
    <div className="decision-number">01</div>
    <div className={decisionClass(gate.decision)}>
      <div className="decision-label">Mission Decision Gate</div>
      <strong>{gate.label}</strong>
      <p>{gate.rationale}</p>
    </div>
    <div className="decision-metrics">
      <div><span>Risk</span><strong>{result.risk.risk_score}</strong></div>
      <div><span>Confidence</span><strong>{result.risk.confidence_score}</strong></div>
      <div><span>Evidence</span><strong>{result.evidence.length}</strong></div>
      <div><span>Sources</span><strong>{new Set(result.evidence.map(e => e.module)).size}</strong></div>
    </div>
  </section>
}

function MissionContext({ result }: { result: InvestigationResult }) {
  const m = result.mission_context
  return <section className="panel context-panel">
    <div className="panel-index">02</div>
    <div className="panel-header"><h2><Target size={18}/> Mission context</h2></div>
    <dl className="context-grid">
      <dt>Type</dt><dd>{m.mission_type}</dd>
      <dt>Target</dt><dd>{m.target}</dd>
      <dt>Mission</dt><dd>{m.mission_event}</dd>
      <dt>Deadline</dt><dd>{m.deadline}</dd>
      <dt>Question</dt><dd>{m.decision_question}</dd>
      <dt>Stakeholders</dt><dd>{m.stakeholders.join(', ')}</dd>
    </dl>
  </section>
}

function TargetSurface({ result }: { result: InvestigationResult }) {
  const p = result.target_profile
  const s = p.public_surface || {}
  const finalUrl = typeof s.final_url === 'string' ? s.final_url : typeof s.checked_url === 'string' ? s.checked_url : ''
  const status = s.status_code ? String(s.status_code) : s.http_checked ? 'checked' : 'not checked'
  const title = typeof s.title === 'string' && s.title ? s.title : 'not available'
  const ipCount = typeof s.resolved_address_count === 'number' ? String(s.resolved_address_count) : '0'
  return <section className="panel surface-panel">
    <div className="panel-index">03</div>
    <div className="panel-header"><h2><Globe2 size={18}/> Target surface</h2></div>
    <dl className="context-grid">
      <dt>Target</dt><dd>{p.display || p.value}</dd>
      <dt>Input</dt><dd>{p.original_query}</dd>
      <dt>Applied query</dt><dd>{p.query_was_expanded ? p.normalized_query : '사용자 입력 그대로 실행'}</dd>
      <dt>Landing URL</dt><dd>{finalUrl || 'not available'}</dd>
      <dt>HTTP</dt><dd>{status}</dd>
      <dt>Title</dt><dd>{title}</dd>
      <dt>Public IPs</dt><dd>{ipCount}</dd>
    </dl>
    {p.collection_notes.length > 0 && <ul className="surface-notes">{p.collection_notes.map((n, i) => <li key={i}>{n}</li>)}</ul>}
  </section>
}

function ExecutiveBrief({ result }: { result: InvestigationResult }) {
  return <section className="panel brief-panel">
    <div className="panel-index">04</div>
    <div className="panel-header"><h2><FileText size={18}/> Executive brief</h2></div>
    <p className="brief-text">{result.report.executive_summary}</p>
    <ul className="brief-list">{result.report.key_findings.slice(0, 4).map((x, i) => <li key={i}>{x}</li>)}</ul>
  </section>
}

function SourceStatus({ result }: { result: InvestigationResult }) {
  return <section className="panel source-panel">
    <div className="panel-index">05</div>
    <div className="panel-header"><h2><Database size={18}/> Source status</h2></div>
    <div className="source-grid">
      {result.plan.map(p => <div className="source-card" key={p.id}>
        <div><strong>{p.module}</strong><span>{p.status}</span></div>
        <p>{p.objective}</p>
        <small>{p.reason || p.query}</small>
      </div>)}
    </div>
  </section>
}

function MilitaryDeployability({ result }: { result: InvestigationResult }) {
  const d = result.deployability
  return <section className="panel deploy-panel">
    <div className="panel-index">06</div>
    <div className="panel-header"><h2><ShieldCheck size={18}/> Military deployability</h2></div>
    <div className="deploy-grid">
      <div><strong>Deployment locations</strong><ul>{d.deployment_locations.map((x, i) => <li key={i}>{x}</li>)}</ul></div>
      <div><strong>Security controls</strong><ul>{d.security_controls.map((x, i) => <li key={i}>{x}</li>)}</ul></div>
      <div><strong>Operational limitations</strong><ul>{d.operational_limitations.map((x, i) => <li key={i}>{x}</li>)}</ul></div>
      <div><strong>Integration points</strong><ul>{d.integration_points.map((x, i) => <li key={i}>{x}</li>)}</ul></div>
    </div>
  </section>
}

function StandardsPanel({ result }: { result: InvestigationResult }) {
  const s = result.standards
  const objectCount = Array.isArray(s.stix_bundle?.objects) ? s.stix_bundle.objects.length : 0
  return <section className="panel standards-panel">
    <div className="panel-index">07</div>
    <div className="panel-header"><h2><GitBranch size={18}/> Standards interoperability</h2></div>
    <div className="standards-summary">
      <div><span>MITRE ATT&CK</span><strong>{s.attack_mappings.length}</strong></div>
      <div><span>STIX Objects</span><strong>{objectCount}</strong></div>
      <div><span>TAXII Ready</span><strong>{s.taxii_readiness.length}</strong></div>
    </div>
    {s.attack_mappings.length ? <div className="mapping-list">{s.attack_mappings.map(m => <article key={m.technique_id + m.evidence_ids.join('-')}>
      <strong>{m.technique_id} · {m.technique_name}</strong>
      <span>{m.tactic} · {Math.round(m.confidence * 100)}%</span>
      <p>{m.rationale}</p>
    </article>)}</div> : <div className="empty-state">현재 actionable evidence가 없어 ATT&CK technique mapping은 생성되지 않았습니다.</div>}
    <ul className="surface-notes">{s.taxii_readiness.map((x, i) => <li key={i}>{x}</li>)}</ul>
  </section>
}

function ActionBoard({ actions, selected, onSelect }: { actions: ActionItem[]; selected?: ActionItem; onSelect: (a: ActionItem) => void }) {
  return <section className="panel action-panel">
    <div className="panel-index">08</div>
    <div className="panel-header"><h2><ListChecks size={18}/> 72-hour mission assurance board</h2></div>
    <div className="action-list">
      {actions.map(a => <button key={a.id} className={selected?.id === a.id ? 'action-row selected' : 'action-row'} onClick={() => onSelect(a)}>
        <span className="window">{a.window}</span>
        <span className="owner">{a.owner}</span>
        <span className="action-text">{a.action}</span>
        <span className="status">{a.status}</span>
      </button>)}
    </div>
  </section>
}

function EvidenceTable({ evidence, selected, onSelect }: { evidence: Evidence[]; selected?: Evidence; onSelect: (ev: Evidence) => void }) {
  return <section className="panel evidence-panel">
    <div className="panel-index">09</div>
    <div className="panel-header"><h2><ShieldCheck size={18}/> Evidence matrix</h2></div>
    {evidence.length ? <div className="table-scroll"><table className="matrix"><thead><tr><th>ID</th><th>Source</th><th>Finding</th><th>Severity</th><th>Time</th><th>Link</th></tr></thead><tbody>{evidence.map(ev => <tr key={ev.id} onClick={() => onSelect(ev)} className={selected?.id === ev.id ? 'selected-row' : ''}><td><strong>{ev.citation}</strong></td><td>{ev.source}<br/><span>{ev.module}</span></td><td><strong>{ev.title}</strong><br/><span>{ev.summary}</span></td><td><span className={severityClass(ev.severity)}>{ev.severity}</span></td><td>{fmtDate(ev.event_time)}</td><td>{proofUrl(ev) ? <a onClick={e => e.stopPropagation()} href={proofUrl(ev)} target="_blank" rel="noreferrer"><ExternalLink size={15}/></a> : '-'}</td></tr>)}</tbody></table></div> : <div className="empty-state">현재 live 조회 범위에서 정규화된 외부 evidence가 없습니다. 내부 로그 검증을 조건으로 mission gate를 검토하세요.</div>}
  </section>
}

function DetailPanel({ detail }: { detail: Detail }) {
  return <section className="panel detail-panel">
    <div className="panel-index">10</div>
    <div className="panel-header"><h2><FileText size={18}/> Detail</h2></div>
    {!detail ? <div className="empty-state">Evidence 또는 action 행을 선택하세요.</div> : detail.kind === 'evidence' ? <EvidenceDetail ev={detail.item}/> : <ActionDetail action={detail.item}/>}
  </section>
}
function EvidenceDetail({ ev }: { ev: Evidence }) {
  return <div className="detail-content">
    <h3>{ev.citation} {ev.title}</h3>
    <p>{ev.summary}</p>
    <dl><dt>Source</dt><dd>{ev.source}</dd><dt>Query</dt><dd>{ev.query}</dd><dt>Event time</dt><dd>{fmtDate(ev.event_time)}</dd><dt>Confidence</dt><dd>{Math.round(ev.confidence * 100)}%</dd></dl>
    <details open><summary>Redacted raw record</summary><pre>{JSON.stringify(rawOf(ev), null, 2)}</pre></details>
  </div>
}
function ActionDetail({ action }: { action: ActionItem }) {
  return <div className="detail-content">
    <h3>{action.window} · {action.owner}</h3>
    <p>{action.action}</p>
    <dl><dt>Status</dt><dd>{action.status}</dd><dt>Success criteria</dt><dd>{action.success_criteria}</dd><dt>Evidence</dt><dd>{action.evidence_ids.join(', ') || 'baseline'}</dd></dl>
  </div>
}

function MissionGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const layout = useMemo(() => {
    const lanes: Record<string, number> = { mission: 90, subject: 285, exposure: 500, impact: 700, control: 915, default: 500 }
    const groups: Record<string, GraphNode[]> = {}
    nodes.forEach(n => { (groups[n.group] ||= []).push(n) })
    const pos: Record<string, {x:number;y:number;n:GraphNode}> = {}
    Object.entries(groups).forEach(([group, arr]) => {
      const x = lanes[group] || lanes.default
      const start = arr.length > 1 ? 120 : 220
      const gap = arr.length > 1 ? Math.min(110, 330 / (arr.length - 1 || 1)) : 0
      arr.forEach((n, i) => { pos[n.id] = { x, y: start + i * gap, n } })
    })
    return pos
  }, [nodes])
  const color = (g: string) => g === 'mission' ? '#002FA7' : g === 'control' ? '#002FA7' : g === 'impact' ? '#FF4F00' : g === 'exposure' ? '#E4002B' : '#111111'
  return <svg className="mission-graph" viewBox="0 0 1040 520" role="img" aria-label="Mission decision graph">
    <defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#111"/></marker></defs>
    {[90,285,500,700,915].map(x => <line key={x} x1={x} y1="60" x2={x} y2="460" className="graph-lane"/>)}
    {edges.map(e => {
      const s = layout[e.source], t = layout[e.target]
      if (!s || !t) return null
      const mid = (s.x + t.x) / 2
      return <g key={e.id}><path className="graph-edge" d={`M ${s.x+70} ${s.y} C ${mid} ${s.y}, ${mid} ${t.y}, ${t.x-80} ${t.y}`} markerEnd="url(#arrow)"/><text x={mid - 32} y={(s.y+t.y)/2 - 5}>{e.label}</text></g>
    })}
    {nodes.map(n => {
      const p = layout[n.id]
      if (!p) return null
      return <g key={n.id} transform={`translate(${p.x-72}, ${p.y-30})`}><rect width="144" height="60" fill="white" stroke={color(n.group)} strokeWidth="2"/><text x="12" y="23" className="node-label">{n.label.length > 22 ? `${n.label.slice(0, 21)}…` : n.label}</text><text x="12" y="43" className="node-type">{n.type}</text></g>
    })}
  </svg>
}
function GraphPanel({ result }: { result: InvestigationResult }) {
  return <section className="panel graph-panel">
    <div className="panel-index">11</div>
    <div className="panel-header"><h2><GitBranch size={18}/> Mission graph</h2></div>
    <MissionGraph nodes={result.graph.nodes} edges={result.graph.edges}/>
  </section>
}

function Timeline({ result }: { result: InvestigationResult }) {
  return <section className="panel timeline-panel">
    <div className="panel-index">12</div>
    <div className="panel-header"><h2><Clock size={18}/> Timeline</h2></div>
    {result.timeline.length ? <div className="timeline-list">{result.timeline.map(t => <div className="time-item" key={t.id}><time>{fmtDate(t.time)}</time><strong>{t.title}</strong><p>{t.summary}</p></div>)}</div> : <div className="empty-state">시간 정보가 있는 이벤트가 없습니다.</div>}
  </section>
}

function ControlsPanel({ result }: { result: InvestigationResult }) {
  return <section className="panel controls-panel">
    <div className="panel-index">13</div>
    <div className="panel-header"><h2><CheckCircle2 size={18}/> Required controls</h2></div>
    <ul className="control-list">{result.decision_gate.required_controls.map((c, i) => <li key={i}><ArrowRight size={15}/>{c}</li>)}</ul>
  </section>
}

function App() {
  const [result, setResult] = useState<InvestigationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [detail, setDetail] = useState<Detail>(null)

  async function run(q: string, apiKey: string) {
    setLoading(true); setError(null); setDetail(null)
    try { setResult(await investigate(q, apiKey)) } catch (e) { setError(e instanceof Error ? e.message : String(e)) } finally { setLoading(false) }
  }

  const selectedEvidence = detail?.kind === 'evidence' ? detail.item : undefined
  const selectedAction = detail?.kind === 'action' ? detail.item : undefined

  return <div className="app"><Topbar/><CommandPanel onRun={run} loading={loading}/>{error && <div className="error">{error}</div>}{!result && !loading && <div className="start-state">실제 사이트 주소를 입력하세요. 예: defense-supplier.co.kr — 사이트 주소만 입력하면 기본 연합훈련 전 Mission Exposure Gate로 자동 확장됩니다.</div>}{result && <main className="result-grid"><DecisionGate result={result}/><MissionContext result={result}/><TargetSurface result={result}/><ExecutiveBrief result={result}/><SourceStatus result={result}/><MilitaryDeployability result={result}/><StandardsPanel result={result}/><ActionBoard actions={result.action_board} selected={selectedAction} onSelect={item => setDetail({kind:'action', item})}/><EvidenceTable evidence={result.evidence} selected={selectedEvidence} onSelect={item => setDetail({kind:'evidence', item})}/><DetailPanel detail={detail}/><GraphPanel result={result}/><Timeline result={result}/><ControlsPanel result={result}/></main>}</div>
}

createRoot(document.getElementById('root')!).render(<App />)
