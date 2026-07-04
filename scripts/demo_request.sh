#!/usr/bin/env bash
set -euo pipefail
curl -sS http://127.0.0.1:8787/api/investigate \
  -H 'Content-Type: application/json' \
  -d '{"query":"www.google.com 관련 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사해줘.","live":true,"classification":"UNCLASSIFIED//CTI","max_results_per_source":5,"time_window_days":3650}' \
  | python3 -m json.tool | sed -n '1,220p'
