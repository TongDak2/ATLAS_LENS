# Atlas Lens Architecture

## Concept

Atlas Lens is a business-moment threat intelligence copilot. It turns fragmented external CTI signals into a concrete decision gate for moments such as product launches, vendor onboarding, M&A due diligence, customer trust responses, executive announcements, and incident pre-checks.

```text
Natural language mission query
  ↓
Business event + target extraction
  ↓
Intent-aware CTI module planner
  ↓
Live StealthMole API connector
  ↓
Exact target filtering + secret redaction
  ↓
Evidence normalization with citation IDs
  ↓
Risk, confidence, exposure DNA
  ↓
GO / GO WITH CONTROLS / NO-GO decision gate
  ↓
72-hour action board + executive brief + mission graph
```

## Components

### 1. Frontend

- Vite + React
- Operator API key input
- Decision Gate first layout
- Mission Context panel
- Source Status panel
- Evidence Matrix
- 72-hour Action Board
- Detail View for evidence/action rows
- Mission Graph
- Timeline
- Required Controls panel

### 2. Backend

- FastAPI
- Pydantic request bounds
- API key auth for operational routes
- In-process rate-limit guardrail
- Evidence-first fusion engine
- StealthMole connector with JWT-per-request authentication
- Async TT search with conservative polling
- Redaction-by-default security controls
- Mock fabrication disabled by default

### 3. Live Data Path

- `CL`, `CB`, `CDS` use synchronous search endpoints.
- `LM`, `GM`, `RM` use monitoring search endpoints.
- `TT` uses target discovery + async search/polling.
- Domain and IP results are post-filtered to reduce false positives.

### 4. Evidence Model

Every conclusion is backed by an `Evidence` object:

```json
{
  "id": "S1",
  "source": "StealthMole CDS",
  "module": "CDS",
  "evidence_type": "stealer_exposure",
  "summary": "감염 단말 기반 계정/호스트 노출 흔적",
  "confidence": 0.88,
  "severity": "critical",
  "citation": "[S1]",
  "redacted": true
}
```

The UI and report refer to cited evidence IDs.

## Business Decision Model

Atlas Lens separates four layers:

1. **Mission Context** — What business moment is being evaluated?
2. **Evidence** — What external CTI signals were observed?
3. **Decision Gate** — Should the business moment proceed?
4. **Action Board** — Who must do what before and after the moment?

Decision values:

- `GO`: no normalized external evidence in the current scope; continue with baseline validation.
- `GO_WITH_CONTROLS`: evidence exists, but it can be handled through required controls and watch actions.
- `NO_GO`: evidence indicates material pre-event risk or multiple high-impact signals require containment first.

## Mission Graph

The graph intentionally maps security evidence to business decisions:

```text
Business Event → Target → Exposure Signal → Business Impact → Required Control
```

This makes the product more than a search dashboard. It explains why a finding matters to a launch, deal, vendor connection, or customer trust response.
