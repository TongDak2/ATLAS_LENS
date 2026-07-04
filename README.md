# ATLAS LENS

**Business-Moment Threat Intelligence Copilot**

ATLAS LENS는 유출 자격증명, 스틸러 로그, 랜섬웨어 발표, 텔레그램 위협 신호처럼 파편화된 외부 위협 정보를 **비즈니스 의사결정**으로 바꾸는 Copilot입니다.

보안팀이 “무엇이 발견됐는가?”에서 멈추지 않고, 제품 출시·벤더 온보딩·M&A·고객 신뢰 대응 같은 중요한 순간에 **GO / GO WITH CONTROLS / NO-GO** 판단과 72시간 액션 플랜을 만들 수 있도록 설계했습니다.

---

## 1. 목적

위협 인텔리전스 데이터는 이미 많습니다. 문제는 데이터가 여러 출처에 흩어져 있고, 분석가가 이를 수작업으로 교차검증한 뒤 비즈니스 언어로 바꾸는 과정이 느리다는 점입니다.

ATLAS LENS는 자연어 질의를 받아 여러 CTI/OSINT 모듈을 오케스트레이션하고, 출처가 명시된 evidence를 기반으로 다음 질문에 답합니다.

```text
지금 이 출시, 계약, 인수, 발표를 진행해도 되는가?
진행한다면 어떤 조건을 걸어야 하는가?
누가 언제까지 무엇을 조치해야 하는가?
```

---

## 2. 핵심 사용 사례

### Product Launch Risk Gate

```text
www.google.com 신규 결제 서비스 출시 전 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Go/No-Go 판단과 72시간 액션 플랜을 만들어줘.
```

### Vendor Onboarding Risk Gate

```text
vendor-pay.co.kr를 신규 결제 벤더로 연동하려고 합니다. 외부 노출, 유출 계정, 랜섬웨어 인접성, 텔레그램 언급을 분석하고 계약 전 필수 보안 조건을 만들어줘.
```

### Deal Cyber Due Diligence

```text
a-company.com 인수 검토 전 외부 유출 계정, 감염 단말, 랜섬웨어 언급을 조사하고 거래 진행 여부와 계약 조건에 넣을 보안 조항을 정리해줘.
```

### Customer Trust Response

```text
고객 보안 질의 대응 전 www.google.com 외부 노출 신호를 확인하고 고객에게 공유 가능한 요약과 내부 조치 목록을 만들어줘.
```

---

## 3. 주요 기능

### 3.1 Mission Query

자연어로 비즈니스 이벤트와 조사 대상을 함께 입력합니다.

지원 대상:

- 도메인: `google.com`, `vendor.co.kr`
- 사이트 주소: `https://www.google.com/path`
- 이메일: `user@google.com`
- IP 주소

사이트 주소만 입력해도 실행됩니다. 예를 들어 `google.com` 또는 `www.google.com 관련 조사`만 입력하면 backend가 이를 다음 기본 업무 시나리오로 자동 확장합니다.

```text
google.com 신규 결제 서비스 출시 전 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Go/No-Go 판단과 72시간 액션 플랜을 만들어줘.
```

응답의 `target_profile`에는 원본 입력, 실제 적용된 질의, 공개 DNS/HTTP 표면, 자동 확장 여부가 포함됩니다. 따라서 운영자는 사이트 주소만 넣어도 해당 사이트 기준의 context와 CTI plan을 바로 확인할 수 있습니다.

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

### 3.3 Decision Gate

조회 결과를 단순 요약하지 않고 다음 셋 중 하나로 판단합니다. Decision Gate는 외부 CTI evidence를 비즈니스 이벤트의 진행 여부로 번역하는 핵심 출력입니다.

```text
GO
GO WITH CONTROLS
NO-GO
```

각 판단은 rationale, required controls, blocking conditions, evidence IDs와 함께 제공됩니다.

#### GO

현재 조회 범위에서 대상 도메인·이메일·IP에 대한 **actionable external evidence**가 확인되지 않은 경우입니다.

예시:

- 유출 계정, combo credential, stealer 감염 단말, 랜섬웨어 공개, 유출 모니터링, 텔레그램 위협 언급이 정규화된 evidence로 확인되지 않음
- 공개 DNS/HTTP target surface만 확인되고, 별도 위협 신호는 없음
- StealthMole live 조회 결과가 없거나, `live=false` 운영 검증에서 mock evidence를 생성하지 않음

권고:

- 출시·계약·고객 대응은 진행 가능
- 단, 외부 신호 부재가 침해 부재를 증명하지는 않으므로 SSO/VPN/Mail/EDR quick sweep를 조건으로 유지
- 이벤트 전후 24시간 watch query와 로그인 이상 징후 모니터링 유지

#### GO WITH CONTROLS

외부 노출 evidence는 확인되지만, 즉시 중단을 단정할 정도로 강한 교차 신호는 부족한 경우입니다.

예시:

- 일부 유출 계정 또는 combo credential이 확인됨
- 단일 모듈에서 유출·협박·텔레그램 언급이 관측됨
- 계정 노출은 있으나 stealer 감염 단말과 랜섬웨어/유출 생태계 신호가 동시에 교차되지는 않음
- Risk Score가 높지 않지만, 이벤트 전 조치가 필요한 evidence가 존재함

권고:

- 진행은 가능하지만 필수 통제를 조건으로 설정
- 유출 계정 후보의 비밀번호 재설정, MFA 상태 확인, SSO/VPN 세션 폐기
- SOC watchlist 등록, 이벤트 전 재조회, 담당자와 완료 기준 지정
- 필수 IAM/EDR/SOC 확인 항목이 마감 전 완료되지 않으면 NO-GO로 재평가

#### NO-GO

현재 상태로 비즈니스 이벤트를 진행하기 전에 추가 검증과 차단 조치가 필요한 경우입니다.

예시:

- 감염 단말 또는 stealer evidence가 확인되고, 랜섬웨어·유출·텔레그램 위협 생태계 신호가 함께 관측됨
- Risk Score가 critical/high 수준으로 상승함
- 유출 계정 또는 감염 단말 정황이 실제 내부 자산과 연결될 가능성이 높음
- 출시·계약·대외 발표 전에 세션 폐기, 계정 조치, 단말 검증 완료 여부가 확인되지 않음

권고:

- 출시·연동·계약·대외 발표를 일시 보류
- IAM, EDR, CMDB, SIEM 검증을 통해 실제 내부 자산 연결 여부 확인
- 감염 가능 단말 격리, 계정 세션 폐기, 관리자 계정 우선 점검
- 조치 완료 후 동일 mission query로 재조회하여 Decision Gate를 다시 산출

#### 판단에 사용하는 evidence 구분

Atlas Lens는 `public_indicator`를 대상 사이트 context로만 사용합니다. 예를 들어 `google.com`의 공개 landing page, HTTP status, public IP 개수는 `target_profile`에 기록되지만, 이 정보만으로 위험 점수를 올리지는 않습니다.

Risk Score와 Decision Gate에 직접 반영되는 evidence는 다음과 같습니다.

- `credential_exposure`
- `combo_exposure`
- `stealer_exposure`
- `ransomware_mention`
- `leak_mention`
- `telegram_mention`
- `vulnerability_pressure`

### 3.4 72-hour Action Board

비즈니스 이벤트 전후로 누가 무엇을 해야 하는지 action board를 생성합니다.

예시:

| Window | Owner | Action |
|---|---|---|
| T-72h | IAM | 유출 계정 후보 확인, 세션 폐기, MFA 검증 |
| T-48h | Endpoint | 스틸러 로그의 username/hostname을 EDR/CMDB와 대조 |
| T-24h | SOC | 랜섬웨어·텔레그램 watch query 등록 |
| T-4h | Business Owner | GO/NO-GO 승인 또는 예외 문서화 |
| T+24h | SOC | 이벤트 이후 로그인·외부 언급 재등장 모니터링 |

### 3.5 Evidence Matrix and Mission Graph

- Evidence Matrix: citation, source, severity, event time, redacted raw record
- Mission Graph: Business Event → Target → Exposure Signal → Business Impact → Required Control
- Timeline: 시간 정보가 있는 외부 노출 신호 정렬
- Executive Brief: 경영진/비즈니스 owner가 바로 읽을 수 있는 요약

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

## 5. 시스템 구성

```text
atlas-lens/
├── backend/                  # FastAPI backend
│   ├── app/api/              # API routes
│   ├── app/connectors/       # CTI connectors
│   ├── app/core/             # config, auth, redaction controls
│   └── app/services/         # entity extraction, planner, fusion engine
├── frontend/                 # React decision console
│   └── src/
├── docs/                     # API, architecture, governance documents
├── examples/                 # request/query examples
├── scripts/                  # run and validation scripts
├── .env.example              # safe config template
├── docker-compose.yml
├── Makefile
└── README.md
```

기술 스택:

| Layer | Technology |
|---|---|
| Backend | Python 3.12+, FastAPI, Pydantic |
| Frontend | React, TypeScript, Vite |
| CTI API | StealthMole External API |
| Visualization | Decision gate, mission graph, evidence matrix, timeline |
| Security | API key auth, request bounds, rate limit, secret redaction |

---

## 6. 설치 전 준비

필수 환경:

- Python 3.12 이상
- Node.js 20 이상
- npm
- StealthMole API Access Key / Secret Key

기본 실행 스크립트는 `python3`를 사용합니다. 시스템의 Python 명령이 다르면 `PYTHON_BIN`으로 지정할 수 있습니다.

```bash
PYTHON_BIN=/opt/homebrew/bin/python3 ./scripts/validate.sh
PYTHON_BIN=/opt/homebrew/bin/python3 ./scripts/run_backend.sh
```

---

## 7. 설치 방법

### 7.1 Repository clone

```bash
git clone https://github.com/TongDak2/ATLAS_LENS.git
cd ATLAS_LENS
```

### 7.2 ATLAS API Key 설정

운영 API는 기본적으로 인증이 필요합니다. 먼저 ATLAS LENS용 API key를 생성합니다.

```bash
cp .env.example .env
python3 - <<'PY'
from pathlib import Path
import secrets
p = Path('.env')
s = p.read_text()
s = s.replace('ATLAS_API_KEY=', f'ATLAS_API_KEY={secrets.token_hex(32)}', 1)
p.write_text(s)
PY
```

### 7.3 StealthMole API Key 설정

StealthMole API key는 repository 밖의 secret 파일에 저장합니다.

```bash
mkdir -p ../.stealthmole
cat > ../.stealthmole/.env <<'EOF'
STEALTHMOLE_BASE_URL=https://hackathon.stealthmole.com
STEALTHMOLE_ACCESS_KEY=your_access_key_here
STEALTHMOLE_SECRET_KEY=your_secret_key_here
EOF
```

다른 위치에 secret 파일을 두고 싶으면 `.env`에서 `STEALTHMOLE_CONFIG_PATH`를 지정합니다.

```bash
STEALTHMOLE_CONFIG_PATH=/secure/path/.stealthmole/.env
```

`.env`, `.env.*`, `.stealthmole/`은 Git에 올라가지 않도록 제외되어 있습니다.

---

## 8. 실행 방법

### 8.1 Backend 실행

```bash
./scripts/run_backend.sh
```

기본 주소:

```text
http://127.0.0.1:8787
```

정상 동작 확인:

```bash
curl -sS http://127.0.0.1:8787/api/health | python3 -m json.tool
```

### 8.2 Frontend 실행

새 터미널에서 실행합니다.

```bash
./scripts/run_frontend.sh
```

웹 콘솔:

```text
http://127.0.0.1:5173
```

Mission Query 아래의 `Operator API Key` 입력칸에는 `.env`의 `ATLAS_API_KEY` 값을 입력합니다. 이 값은 browser session storage에만 저장되며 API 호출 시 `X-Atlas-API-Key` 헤더로 전달됩니다.

### 8.3 Docker Compose 실행

```bash
export ATLAS_API_KEY=$(grep '^ATLAS_API_KEY=' .env | cut -d= -f2-)
docker compose up -d --build
```

Compose의 backend/frontend 포트는 기본적으로 `127.0.0.1`에만 바인딩됩니다. 외부 네트워크에 직접 노출하지 말고 SSO/VPN/reverse proxy 뒤에 배치하세요.

서비스 중지:

```bash
docker compose down
```

---

## 9. API 사용 방법

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
    "query": "www.google.com 신규 결제 서비스 출시 전 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 Go/No-Go 판단과 72시간 액션 플랜을 만들어줘.",
    "live": true,
    "max_results_per_source": 5,
    "time_window_days": 3650
  }' | python3 -m json.tool
```

---

## 10. 운영 배포 권장 구성

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
```

운영 권장 사항:

- Backend는 내부망 또는 승인된 분석망에서만 노출합니다.
- Frontend 앞단에 TLS, SSO, VPN, 접근제어를 적용합니다.
- live investigation에는 in-process rate limit이 적용되며, 운영 환경에서는 reverse proxy/API gateway rate limit을 추가로 적용하세요.
- 모든 decision gate와 action board는 감사 로그로 남기는 것을 권장합니다.
- 외부 CTI 결과는 내부 로그와 교차검증한 뒤 incident 또는 business exception으로 확정합니다.

---

## 11. 검증

```bash
./scripts/validate.sh
```

검증 내용:

- Python runtime selection
- API key auth, invalid key, missing key
- request bounds
- docs/OpenAPI production lock-down
- URL/domain/email/IP 추출
- intent-aware module planning
- invalid query rejection
- mock evidence 비활성화
- frontend production build

---

## 12. Git 업로드 시 제외해야 하는 파일

```text
.env
.env.*
.stealthmole/
backend/.venv/
frontend/node_modules/
frontend/dist/
__pycache__/
.pytest_cache/
.DS_Store
logs/
exports/
실제 raw credential dump
API key가 포함된 모든 파일
```
