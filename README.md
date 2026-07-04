# ATLAS LENS

**Mission Exposure Decision Gate**

ATLAS LENS는 유출 자격증명, 감염 단말 흔적, 랜섬웨어 공개, 유출 모니터링, 텔레그램 위협 신호처럼 파편화된 외부 CTI/OSINT 데이터를 **군 임무 진행 판단**으로 바꾸는 Copilot입니다.

작전·훈련·방산 협력사 연동·대외 공개·침해 주장 검증 전에 분석가가 여러 출처를 수작업으로 교차 확인하는 병목을 줄이고, evidence 기반 **MISSION GO / MISSION GO WITH CONTROLS / MISSION NO-GO** 판단과 72시간 조치 계획을 생성합니다.

---

## 1. 목적

위협 인텔리전스 데이터의 문제는 부족함이 아니라 파편화입니다. 유출 계정은 credential feed에, 감염 단말 흔적은 stealer dataset에, 랜섬웨어 발표는 별도 모니터링에, 거래 정황은 텔레그램 채널에 흩어져 있습니다.

ATLAS LENS는 자연어 질의를 받아 여러 CTI 모듈을 오케스트레이션하고, 출처가 붙은 evidence를 기반으로 다음 질문에 답합니다.

```text
이 작전, 훈련, 협력사 연동, 포털 공개를 진행해도 되는가?
진행한다면 어떤 통제를 조건으로 걸어야 하는가?
누가 언제까지 무엇을 조치해야 하는가?
```

---

## 2. 핵심 사용 사례

### Joint Training Exposure Gate

```text
다음 주 연합훈련 전 defense-supplier.co.kr 관련 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Mission GO/NO-GO 판단과 72시간 조치 계획을 만들어줘.
```

### Command Portal Release Gate

```text
훈련용 지휘통제 포털 c2-training.example.mil 공개 전 외부 노출 신호를 조사하고 임무 진행 가능 여부를 판단해줘.
```

### Defense Supplier Connection Gate

```text
방산 협력사 supplier.example.kr 임무망 연동 전 유출 계정, 감염 단말, 랜섬웨어 인접성, 텔레그램 언급을 분석하고 연결 조건을 만들어줘.
```

### Incident Claim Validation Gate

```text
example.mil 랜섬웨어 피해 주장 관련 외부 유출 언급과 텔레그램 위협 신호를 조사하고 SOC 대응 승격 여부를 판단해줘.
```

---

## 3. 주요 기능

### 3.1 Mission Query

자연어로 임무 상황과 조사 대상을 함께 입력합니다.

지원 대상:

- 도메인: `defense-supplier.co.kr`, `example.mil`
- 사이트 주소: `https://c2-training.example.mil/path`
- 이메일: `operator@example.mil`
- IP 주소

사이트 주소만 입력해도 실행됩니다. 예를 들어 `defense-supplier.co.kr` 또는 `defense-supplier.co.kr 관련 조사`만 입력하면 backend가 이를 기본 임무 시나리오로 자동 확장합니다.

```text
defense-supplier.co.kr 연합훈련 전 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Mission GO/NO-GO 판단과 72시간 조치 계획을 만들어줘.
```

응답의 `target_profile`에는 원본 입력, 실제 적용된 질의, 공개 DNS/HTTP 표면, 자동 확장 여부가 포함됩니다.

조사 대상이 없는 문장, 예를 들어 `hello` 같은 입력은 frontend와 backend API 양쪽에서 실행하지 않고 정확한 조사 대상을 요구합니다.

### 3.2 Multi-source CTI Orchestration

StealthMole API와 연동해 다음 모듈을 조회합니다.

| Module | Purpose |
|---|---|
| `CL` | 유출 계정 조회 |
| `CB` | 콤보 리스트 기반 계정 노출 조회 |
| `CDS` | 감염 단말·스틸러 로그 기반 노출 조회 |
| `LM` | 일반 유출 모니터링 |
| `GM` | 정부·공공 관련 노출 모니터링 |
| `RM` | 랜섬웨어 언급 모니터링 |
| `TT` | 텔레그램 위협 신호 조회 |

### 3.3 Mission Context

입력 문장을 다음 임무 상황 중 하나로 자동 분류합니다.

| Mission Type | Meaning |
|---|---|
| `joint_training` | 연합훈련 또는 교육훈련 전 외부 노출 검증 |
| `operation_support` | 작전·임무 지원 전 외부 위협 노출 검증 |
| `defense_supplier` | 방산 협력사·공급망·외부 연동 전 검증 |
| `public_release` | 훈련용 포털·지휘통제 서비스·대외 공개 전 검증 |
| `incident_claim` | 침해 주장 또는 외부 위협 주장 검증 |
| `mission_assurance` | 일반 중요 임무 결정 전 검증 |

### 3.4 Mission Decision Gate

조회 결과를 단순 요약하지 않고 다음 셋 중 하나로 판단합니다.

```text
MISSION GO
MISSION GO WITH CONTROLS
MISSION NO-GO
```

각 판단은 rationale, required controls, blocking conditions, evidence IDs와 함께 제공됩니다.

#### MISSION GO

현재 조회 범위에서 대상 도메인·이메일·IP에 대한 **actionable external evidence**가 확인되지 않은 경우입니다.

예시:

- 유출 계정, combo credential, stealer 감염 단말, 랜섬웨어 공개, 유출 모니터링, 텔레그램 위협 언급이 정규화된 evidence로 확인되지 않음
- 공개 DNS/HTTP target surface만 확인되고, 별도 위협 신호는 없음
- StealthMole live 조회 결과가 없거나, `live=false` 운영 검증에서 mock evidence를 생성하지 않음

권고:

- 임무·훈련·연동·공개는 진행 가능
- 단, 외부 신호 부재가 침해 부재를 증명하지는 않으므로 SSO/VPN/Mail/EDR quick sweep를 조건으로 유지
- 임무 전후 24시간 watch query와 로그인 이상 징후 모니터링 유지

#### MISSION GO WITH CONTROLS

외부 노출 evidence는 확인되지만, 즉시 중단을 단정할 정도로 강한 교차 신호는 부족한 경우입니다.

예시:

- 일부 유출 계정 또는 combo credential이 확인됨
- 단일 모듈에서 유출·협박·텔레그램 언급이 관측됨
- 계정 노출은 있으나 stealer 감염 단말과 랜섬웨어/유출 생태계 신호가 동시에 교차되지는 않음
- Risk Score가 높지 않지만, 임무 전 조치가 필요한 evidence가 존재함

권고:

- 진행은 가능하지만 필수 통제를 조건으로 설정
- 유출 계정 후보의 비밀번호 재설정, MFA 상태 확인, SSO/VPN 세션 폐기
- SOC watchlist 등록, 임무 전 재조회, 담당자와 완료 기준 지정
- 필수 IAM/EDR/SOC 확인 항목이 마감 전 완료되지 않으면 MISSION NO-GO로 재평가

#### MISSION NO-GO

현재 상태로 임무 이벤트를 진행하기 전에 추가 검증과 차단 조치가 필요한 경우입니다.

예시:

- 감염 단말 또는 stealer evidence가 확인되고, 랜섬웨어·유출·텔레그램 위협 생태계 신호가 함께 관측됨
- Risk Score가 critical/high 수준으로 상승함
- 유출 계정 또는 감염 단말 정황이 실제 군 자산 또는 방산 협력사 자산과 연결될 가능성이 높음
- 훈련·작전·연동·대외 공개 전에 세션 폐기, 계정 조치, 단말 검증 완료 여부가 확인되지 않음

권고:

- 훈련·연동·공개·임무 진행을 일시 보류
- IAM, EDR, CMDB, SIEM 검증을 통해 실제 내부 자산 연결 여부 확인
- 감염 가능 단말 격리, 계정 세션 폐기, 관리자 계정 우선 점검
- 조치 완료 후 동일 mission query로 재조회하여 Decision Gate를 다시 산출

#### 판단에 사용하는 evidence 구분

Atlas Lens는 `public_indicator`를 대상 사이트 context로만 사용합니다. 예를 들어 공개 landing page, HTTP status, public IP 개수는 `target_profile`에 기록되지만, 이 정보만으로 위험 점수를 올리지는 않습니다.

Risk Score와 Decision Gate에 직접 반영되는 evidence는 다음과 같습니다.

- `credential_exposure`
- `combo_exposure`
- `stealer_exposure`
- `ransomware_mention`
- `leak_mention`
- `telegram_mention`
- `vulnerability_pressure`

### 3.5 72-hour Mission Assurance Board

임무 전후로 누가 무엇을 해야 하는지 action board를 생성합니다.

| Window | Owner | Action |
|---|---|---|
| T-72h | IAM | 유출 계정 후보 확인, 세션 폐기, MFA 검증 |
| T-48h | Endpoint | 스틸러 로그의 username/hostname을 EDR/CMDB와 대조 |
| T-24h | SOC | 랜섬웨어·텔레그램 watch query 등록 |
| T-4h | Mission Owner | Mission GO/NO-GO 승인 또는 예외 문서화 |
| T+24h | SOC | 임무 이후 로그인·외부 언급 재등장 모니터링 |

### 3.6 Military Deployability Panel

운영 환경에서 바로 검토할 수 있도록 다음 정보를 API와 UI에 포함합니다.

- 배포 위치: 인터넷 연결 CTI 분석망, 군 SOC, 사이버작전센터, Mission Assurance Review Cell, 방산 협력사 보안 심사 워크플로
- 보안 통제: API key 인증, redaction, rate limit, production docs 비활성화, analyst review
- 제한사항: 외부 신호는 내부 침해 증명이 아님, 내부 IAM/EDR/SIEM 검증 필요, 폐쇄망 단독 배포 시 승인된 CTI relay 필요
- 연계 지점: IAM, EDR, MDM, CMDB, SIEM, SOAR, STIX/TAXII repository

### 3.7 MITRE ATT&CK / STIX / TAXII 연계

ATLAS LENS는 evidence type을 MITRE ATT&CK technique으로 매핑하고, API 응답에 STIX 2.1 JSON bundle 형태의 export object를 포함합니다. 이 bundle은 정책 검토 후 내부 TAXII gateway 또는 threat-intel repository로 전달할 수 있습니다.

참고 표준:

- MITRE ATT&CK CTI Training: https://attack.mitre.org/resources/training/cti/
- OASIS STIX Introduction: https://oasis-open.github.io/cti-documentation/stix/intro.html
- CISA AIS TAXII Server Connection Guide: https://www.cisa.gov/resources-tools/resources/automated-indicator-sharing-ais-taxii-server-connection-guide

### 3.8 Evidence Matrix and Mission Graph

- Evidence Matrix: citation, source, severity, event time, redacted raw record
- Mission Graph: Mission Event → Target → Exposure Signal → Mission Impact → Required Control
- Timeline: 시간 정보가 있는 외부 노출 신호 정렬
- Executive Brief: 지휘관·임무 담당자·SOC가 바로 읽을 수 있는 요약

---

## 4. 보안 원칙

ATLAS LENS는 승인된 방어 목적의 분석 도구입니다.

- 실제 exploit, 침투 절차, 공격 자동화 기능을 제공하지 않습니다.
- `/api/quotas`, `/api/investigate`는 `X-Atlas-API-Key` 또는 `Authorization: Bearer` 인증 없이는 실행되지 않습니다.
- production 기본값에서는 `/docs`, `/openapi.json`을 비활성화합니다.
- raw password, token, cookie, secret은 기본적으로 마스킹합니다.
- 외부 CTI 데이터는 신뢰된 명령이 아니라 비신뢰 데이터로 취급합니다.
- 외부 노출 신호만으로 침해를 확정하지 않고 내부 IAM/EDR/SIEM 로그와 함께 검증해야 합니다.

---

## 5. 로컬 실행

### 5.1 요구사항

- Python 3.12 이상
- Node.js 20 이상 권장
- npm
- StealthMole API credential

### 5.2 환경 변수

```bash
cp .env.example .env
```

`.env` 예시:

```bash
ATLAS_API_KEY=change-this-local-operator-key
ATLAS_DOCS_ENABLED=false
ATLAS_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

StealthMole credential은 repo 밖에 보관하는 것을 권장합니다.

```bash
mkdir -p ../.stealthmole
cat > ../.stealthmole/.env <<'EOF'
STEALTHMOLE_BASE_URL=https://hackathon.stealthmole.com
STEALTHMOLE_ACCESS_KEY=...
STEALTHMOLE_SECRET_KEY=...
EOF
```

### 5.3 Backend

```bash
./scripts/run_backend.sh
```

Backend:

```text
http://127.0.0.1:8787
```

### 5.4 Frontend

```bash
./scripts/run_frontend.sh
```

Frontend:

```text
http://127.0.0.1:5173
```

### 5.5 Validation

```bash
make validate
```

검증 항목:

- Python 3.12+ 런타임 선택
- API key 인증
- rate limit guardrail
- invalid query rejection
- email/domain/IP parsing
- IP-specific planning
- bare-site mission expansion
- mission decision result schema
- deployability/standards response sections
- frontend production build

---

## 6. API 사용 방법

### Health Check

```bash
curl -sS http://127.0.0.1:8787/api/health | python3 -m json.tool
```

### Quota Check

```bash
curl -sS http://127.0.0.1:8787/api/quotas \
  -H "X-Atlas-API-Key: $ATLAS_API_KEY" | python3 -m json.tool
```

### Live Investigation

```bash
curl -sS http://127.0.0.1:8787/api/investigate \
  -H 'Content-Type: application/json' \
  -H "X-Atlas-API-Key: $ATLAS_API_KEY" \
  -d '{
    "query": "다음 주 연합훈련 전 defense-supplier.co.kr 관련 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Mission GO/NO-GO 판단과 72시간 조치 계획을 만들어줘.",
    "live": true,
    "max_results_per_source": 5,
    "time_window_days": 3650
  }' | python3 -m json.tool
```

Response sections:

- `mission_context`
- `target_profile`
- `decision_gate`
- `deployability`
- `standards`
- `action_board`
- `plan`
- `evidence`
- `risk`
- `exposure_dna`
- `next_best_questions`
- `graph`
- `timeline`
- `report`
- `safety`

---

## 7. 운영 배포 권장 구성

```text
Analyst Browser
  ↓ HTTPS / SSO / VPN
Reverse Proxy / WAF / API Gateway
  ↓
ATLAS LENS Frontend
  ↓ X-Atlas-API-Key
ATLAS LENS Backend API
  ↓
Approved CTI API / StealthMole
  ↓
Internal IAM, EDR, SIEM, Mail, VPN logs for validation
  ↓
STIX/TAXII gateway or internal CTI repository
```

Docker compose는 기본적으로 localhost에만 port를 bind합니다.

```yaml
ports:
  - "127.0.0.1:8787:8787"
  - "127.0.0.1:5173:5173"
```

운영 배포 시에는 reverse proxy 인증, SSO/VPN, audit log, gateway rate limit, network allowlist를 추가해야 합니다.

---

## 8. Repository Safety

Git에 포함하지 않는 항목:

- `.env`
- `.env.*`
- `.stealthmole/`
- `.venv/`
- `node_modules/`
- build output

