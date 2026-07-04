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

Requires `X-Atlas-API-Key` or `Authorization: Bearer <token>`. Returns StealthMole quota information if credentials are configured. This endpoint does not expose local secrets.

## Investigate

```http
POST /api/investigate
Content-Type: application/json
X-Atlas-API-Key: <ATLAS_API_KEY>
```

Request:

```json
{
  "query": "www.google.com 신규 결제 서비스 출시 전 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Go/No-Go 판단과 72시간 액션 플랜을 만들어줘.",
  "time_window_days": 3650,
  "classification": "UNCLASSIFIED//CTI",
  "live": true,
  "max_results_per_source": 5,
  "include_public_feeds": true
}
```

Authentication:

- `GET /api/quotas` and `POST /api/investigate` require `X-Atlas-API-Key: <ATLAS_API_KEY>` or `Authorization: Bearer <ATLAS_API_KEY>`.
- Missing or invalid keys return `401`.
- If the server has no `ATLAS_API_KEY` configured, authenticated operational routes fail closed with `503`.
- In production, `/docs`, `/redoc`, and `/openapi.json` are disabled unless `ATLAS_DOCS_ENABLED=true`.

Operational behavior:

- `live=true` is the default.
- The backend requires a concrete domain, URL, email address, or IP address. Keyword-only requests such as `hello` return `422 Unprocessable Entity`.
- Bare site inputs such as `google.com` are automatically expanded to the default product-launch risk gate, so operators do not need to type the full “유출 계정/감염 단말/랜섬웨어/텔레그램/Go-No-Go” query each time.
- With `include_public_feeds=true`, Atlas Lens collects a small public DNS/HTTP target profile for public domains and returns it as `target_profile`; this is context evidence, not a vulnerability scan.
- If live credentials are missing, Atlas Lens returns failed source status and does not fabricate evidence.
- `live=false` does not generate mock evidence in operational mode.
- Passwords, tokens, API keys, and secrets are redacted before response serialization.
- Request fields are bounded: `query` 2-2000 chars, `classification` max 128 chars, `time_window_days` 1-3650, `max_results_per_source` 1-50.
- Authenticated requests are protected by an in-process rate limit; production deployments should still add gateway/proxy rate limiting.

Response sections:

- `mission_context`
- `target_profile`
- `decision_gate`
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

## Invalid target example

```json
{
  "query": "hello",
  "live": false
}
```

Response:

```json
{
  "detail": "A concrete investigation target is required. Include a real domain, URL, email address, or IP address."
}
```

HTTP status: `422 Unprocessable Entity`.

## Authentication failure example

```bash
curl -i http://127.0.0.1:8787/api/quotas
```

Expected status: `401 Unauthorized`.
