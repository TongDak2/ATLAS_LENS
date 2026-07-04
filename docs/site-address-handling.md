# Site Address Handling

Atlas Lens accepts real site addresses and normalizes them into mission investigation targets.

## Examples

```text
다음 주 연합훈련 전 defense-supplier.co.kr 관련 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Mission GO/NO-GO 판단과 72시간 조치 계획을 만들어줘.
```

```text
훈련용 지휘통제 포털 c2-training.example.mil 공개 전 외부 노출 신호를 조사하고 임무 진행 가능 여부를 판단해줘.
```

## Normalization

- `www.defense-supplier.co.kr` → `defense-supplier.co.kr`
- `https://c2-training.example.mil/path` → `c2-training.example.mil`
- Email domains are extracted from `operator@example.mil` without scanning partial domains inside the email string.
- `8.8.8.8` remains an IP entity and is planned as `ip:8.8.8.8`.

## Bare-site default mission

If the input contains only a site address or a low-information request such as `defense-supplier.co.kr`, `defense-supplier.co.kr 관련 조사`, or `https://c2-training.example.mil`, Atlas Lens expands it to the default operational mission:

```text
defense-supplier.co.kr 연합훈련 전 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Mission GO/NO-GO 판단과 72시간 조치 계획을 만들어줘.
```

This creates a broad mission-assurance plan: `CL`, `CB`, `CDS`, `LM`, `RM`, and `TT`. If the user already provides a narrower intent, for example `defense-supplier.co.kr 관련 유출 계정 조사`, Atlas Lens keeps the credential-focused plan.

## Target validation

The API requires at least one concrete domain, URL, email address, or IP address. Keyword-only inputs such as `hello` are rejected with HTTP `422`.

## Exact-domain and IP filtering

Live API responses are post-filtered so that substring false positives are reduced. IP-specific queries are likewise filtered against structured IP fields and boundary-aware IP text matches.

## Evidence policy

- Mock fabrication is disabled by default.
- If no live evidence is returned, Atlas Lens reports zero actionable evidence and recommends baseline internal log validation instead of inventing findings.
- Sensitive fields remain redacted.
