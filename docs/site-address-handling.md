# Site Address Handling

Atlas Lens accepts real site addresses and normalizes them into the target used for live CTI searches.

## Examples

```text
www.google.com 신규 결제 서비스 출시 전 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Go/No-Go 판단과 72시간 액션 플랜을 만들어줘.
```

```text
vendor-pay.co.kr 신규 벤더 계약 전 유출 계정과 랜섬웨어 언급을 조사하고 계약 조건을 만들어줘.
```

## Normalization

- `www.google.com` → `google.com`
- `https://sub.example.org/path` → `sub.example.org`
- Email domains are extracted from `user@example.org` without scanning partial domains inside the email string.
- `8.8.8.8` remains an IP entity and is planned as `ip:8.8.8.8`.

## Bare-site default mission

If the input contains only a site address or a low-information request such as `google.com`, `google.com 관련 조사`, or `https://www.google.com`, Atlas Lens expands it to the default operational mission:

```text
google.com 신규 결제 서비스 출시 전 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Go/No-Go 판단과 72시간 액션 플랜을 만들어줘.
```

This creates the same broad plan that an analyst would normally type by hand: `CL`, `CB`, `CDS`, `LM`, `RM`, and `TT`. If the user already provides a more specific intent, for example `google.com 관련 유출 계정 조사`, Atlas Lens keeps the narrower credential-focused plan.

## Target profile

Every investigation returns `target_profile`:

- `original_query`: user input
- `normalized_query`: query actually used by the planner
- `query_was_expanded`: whether the bare-site default mission was applied
- `public_surface`: public DNS/HTTP landing-page context for the target domain when `live=true` and `include_public_feeds=true`

## Target validation

The API requires at least one concrete domain, URL, email address, or IP address. Keyword-only inputs such as `hello` are rejected with HTTP `422`.

## Intent-aware routing

- `계정 유출 조사` → `CL`, `CB`
- `감염 단말` → `CDS`
- `랜섬웨어` → `RM`
- `텔레그램` → `TT`
- `정부/공공/.go.kr/.gov/.mil` → `GM` is added when monitoring is requested
- IP-only target such as `8.8.8.8 외부 노출 확인` → `CDS`, `LM` using `ip:8.8.8.8`; broader/ransomware/telegram intent adds `GM`, `RM`, `TT` with the same IP-specific query prefix.

## Exact-domain and IP filtering

Live API responses are post-filtered so that substring false positives are reduced. For example, `grand4d.tech` is not treated as evidence for `d4d.tech`, while `sub.d4d.tech` is accepted. IP-specific queries are likewise filtered against structured IP fields and boundary-aware IP text matches.

## Evidence policy

- Mock fabrication is disabled by default.
- If no live evidence is returned, Atlas Lens reports zero evidence and recommends baseline internal log validation instead of inventing findings.
- Sensitive fields remain redacted.
