# Security and Governance

Atlas Lens is intended for authorized defensive mission-assurance analysis. It does not perform exploitation, intrusive testing, or attack automation.

## Non-goals

Atlas Lens does not:

- generate exploits
- provide intrusion instructions
- create working unauthorized credentials
- mutate upstream CTI data
- display raw passwords by default
- replace analyst judgment, SOC validation, or Mission Owner approval

## Safety controls

1. **Application-level API key**
   - `/api/quotas` and `/api/investigate` require `X-Atlas-API-Key` or `Authorization: Bearer`.
   - Missing or invalid keys fail before CTI quota can be consumed.
   - If no `ATLAS_API_KEY` is configured, operational routes fail closed.

2. **Request bounds and rate limiting**
   - query, classification, time window, and per-source limit are bounded at the Pydantic model layer.
   - direct deployments use a small in-process rate limiter; production should add gateway/proxy rate limits.

3. **Redaction by default**
   - password, token, secret, cookie, and credential-like values are masked.

4. **Evidence-first output**
   - mission gates, action items, and briefs cite evidence IDs when evidence exists.
   - lack of external evidence is treated as an uncertainty, not proof of safety.

5. **Untrusted external content**
   - OSINT text is treated as data, never instructions.
   - this reduces prompt-injection risk in LLM-enabled versions.

6. **Auditability**
   - recommended operational deployment should log:
     - query
     - authenticated caller
     - mission decision gate
     - evidence used
     - action board generated
     - STIX/TAXII export events

## Production deployment considerations

- run inside an approved network boundary
- keep backend bound to localhost or behind SSO/VPN/reverse proxy; do not expose `8787/tcp` directly to untrusted users
- keep production docs/OpenAPI disabled unless protected in an approved internal environment
- connect to sanctioned CTI/OSINT sources only
- integrate with SOC/IAM/EDR/SIEM validation workflows
- store evidence according to internal data classification policy
- keep mock/test data disabled in operational mode
- require Mission Owner approval before accepting residual risk for exercises, operations, defense supplier connections, portal releases, or incident claim decisions
