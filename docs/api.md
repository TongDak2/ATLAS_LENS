# API

## Health

```http
GET /api/health
```

Returns generic liveness only. It intentionally does not reveal whether upstream CTI credentials are configured.

## Quotas

```http
GET /api/quotas
X-Atlas-API-Key: <ATLAS_API_KEY>
```

Requires `X-Atlas-API-Key` or `Authorization: Bearer <token>`.

## Investigate

```http
POST /api/investigate
Content-Type: application/json
X-Atlas-API-Key: <ATLAS_API_KEY>
```

Request:

```json
{
  "query": "다음 주 연합훈련 전 defense-supplier.co.kr 관련 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Mission GO/NO-GO 판단과 72시간 조치 계획을 만들어줘.",
  "time_window_days": 3650,
  "classification": "UNCLASSIFIED//CTI",
  "live": true,
  "max_results_per_source": 5,
  "include_public_feeds": true
}
```

Operational behavior:

- `live=true` is the default.
- The backend requires a concrete domain, URL, email address, or IP address.
- Keyword-only requests such as `hello` return `422 Unprocessable Entity`.
- Bare site inputs such as `defense-supplier.co.kr` are automatically expanded to the default joint-training Mission Exposure Gate.
- With `include_public_feeds=true`, Atlas Lens collects a small public DNS/HTTP target profile for public domains; this is context evidence, not a vulnerability scan.
- If live credentials are missing, Atlas Lens returns failed source status and does not fabricate evidence.
- `live=false` does not generate mock evidence in operational mode.
- Passwords, tokens, API keys, and secrets are redacted before response serialization.
- Request fields are bounded: `query` 2-2000 chars, `classification` max 128 chars, `time_window_days` 1-3650, `max_results_per_source` 1-50.

Response sections:

- `mission_context`
- `target_profile`
- `decision_gate`
- `deployability`
- `standards`
- `action_board`
- `entities`
- `plan`
- `evidence`
- `risk`
- `exposure_dna`
- `next_best_questions`
- `graph`
- `timeline`
- `report`
- `safety`

## Standards output

`standards.attack_mappings` maps evidence to MITRE ATT&CK techniques where applicable.

`standards.stix_bundle` contains a STIX 2.1-style JSON bundle with redacted evidence objects and a report object. The bundle can be forwarded to an approved TAXII gateway or internal threat-intel repository after policy review.
