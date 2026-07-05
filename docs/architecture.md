# Architecture

```text
Mission Query
  ↓
Target extraction and mission-context classification
  ↓
Planner: CL / CB / CDS / LM / GM / RM / TT
  ↓
StealthMole connector and public target profile collector
  ↓
Evidence normalization and redaction
  ↓
Risk model and Decision Gate
  ↓
72-hour Mission Assurance Board
  ↓
Military Deployability Panel
  ↓
MITRE ATT&CK mapping + STIX/TAXII-ready export
  ↓
Frontend mission console / API response
```

## Mission Context Model

Atlas Lens classifies mission queries into:

- `joint_training`
- `operation_support`
- `defense_supplier`
- `public_release`
- `incident_claim`
- `mission_assurance`

## Decision Model

The decision gate returns:

- `GO`
- `GO WITH CONTROLS`
- `NO-GO`

The score is driven by actionable evidence: credential exposure, combo exposure, stealer exposure, ransomware mention, leak mention, Telegram mention, and vulnerability pressure. Public surface information is context only.

## Standards Model

The backend produces:

- MITRE ATT&CK mappings for relevant evidence.
- STIX 2.1-style bundle containing redacted evidence and report objects.
- TAXII readiness notes for approved gateway or internal CTI repository integration.
