#!/usr/bin/env bash
set -euo pipefail
ATLAS_API_KEY="${ATLAS_API_KEY:-change-this-local-operator-key}"
curl -sS http://127.0.0.1:8787/api/investigate \
  -H 'Content-Type: application/json' \
  -H "X-Atlas-API-Key: ${ATLAS_API_KEY}" \
  -d '{"query":"다음 주 연합훈련 전 defense-supplier.co.kr 관련 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 GO/NO-GO 판단과 72시간 조치 계획을 만들어줘.","live":true,"classification":"UNCLASSIFIED//CTI","max_results_per_source":5,"time_window_days":3650}' \
  | python3 -m json.tool
