#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "error: Python interpreter not found: $PYTHON_BIN" >&2
  echo "Set PYTHON_BIN to a Python 3.12+ binary, e.g. PYTHON_BIN=/opt/homebrew/bin/python3" >&2
  exit 127
fi
"$PYTHON_BIN" - <<'PY'
import sys
if sys.version_info < (3, 12):
    raise SystemExit(f"error: Python 3.12+ is required, got {sys.version.split()[0]}")
print(f"using Python {sys.version.split()[0]}")
PY
cd "$ROOT/backend"
if [ ! -d .venv ]; then "$PYTHON_BIN" -m venv .venv; fi
source .venv/bin/activate
pip install -q -r requirements.txt
python - <<'PY'
from fastapi.testclient import TestClient

from types import SimpleNamespace

from fastapi import HTTPException

from app.core.auth import AuthContext, _RATE_BUCKETS, enforce_rate_limit
from app.core.config import settings
from app.core.security import redact
from app.main import app
from app.models import InvestigationRequest
from app.services.entity_extractor import extract_entities, has_investigable_target
from app.services.investigator import Investigator
from app.services.planner import build_plan
from app.services.query_normalizer import normalize_query

settings.atlas_api_key = 'validate-test-key'
_RATE_BUCKETS.clear()
client = TestClient(app, base_url='http://localhost')
headers = {'X-Atlas-API-Key': settings.atlas_api_key}
valid_body = {
    'query': '다음 주 연합훈련 전 defense-supplier.co.kr 관련 유출 계정, 감염 단말, 랜섬웨어 언급, 텔레그램 위협 신호를 조사하고 GO/NO-GO 판단과 72시간 조치 계획을 만들어줘.',
    'live': False,
    'classification': 'UNCLASSIFIED//CTI',
    'max_results_per_source': 5,
    'time_window_days': 3650,
}

health = client.get('/api/health')
assert health.status_code == 200, health.text
assert health.headers.get('x-content-type-options') == 'nosniff', dict(health.headers)
assert health.headers.get('x-frame-options') == 'DENY', dict(health.headers)
assert health.headers.get('referrer-policy') == 'no-referrer', dict(health.headers)
assert health.headers.get('cache-control') == 'no-store', dict(health.headers)
assert health.headers.get('x-request-id'), dict(health.headers)
assert 'stealthmole_configured' not in health.json(), health.json()
assert client.get('/openapi.json').status_code == 404
assert client.get('/docs').status_code == 404

assert client.get('/api/quotas').status_code == 401
assert client.post('/api/investigate', json=valid_body).status_code == 401
assert client.post('/api/investigate', headers={'X-Atlas-API-Key': 'wrong'}, json=valid_body).status_code == 401

# Direct rate-limit guardrail check without touching live CTI.
old_limit = settings.atlas_rate_limit_requests
settings.atlas_rate_limit_requests = 1
_RATE_BUCKETS.clear()
fake_request = SimpleNamespace(client=SimpleNamespace(host='127.0.0.1'))
ctx = AuthContext(subject='validate-caller')
enforce_rate_limit(ctx, fake_request, live=False)
try:
    enforce_rate_limit(ctx, fake_request, live=False)
except HTTPException as exc:
    assert exc.status_code == 429, exc.status_code
else:
    raise AssertionError('second request should be rate limited')
settings.atlas_rate_limit_requests = old_limit
_RATE_BUCKETS.clear()

q = valid_body['query']
entities = extract_entities(q)
assert any(e.type == 'domain' and e.value == 'defense-supplier.co.kr' for e in entities), entities
plan = build_plan(entities, 5, q)
assert [p.module for p in plan] == ['CL', 'CB', 'CDS', 'LM', 'RM', 'TT'], [p.module for p in plan]
res = client.post('/api/investigate', headers=headers, json=valid_body)
assert res.status_code == 200, res.text
body = res.json()
assert body['product'] == 'Atlas Lens'
assert body['mission_context']['mission_type'] == 'joint_training', body['mission_context']
assert body['decision_gate']['decision'] in {'GO', 'GO_WITH_CONTROLS', 'NO_GO'}, body['decision_gate']
assert len(body['action_board']) >= 4, body['action_board']
assert body['target_profile']['display'] == 'defense-supplier.co.kr', body['target_profile']
assert body['target_profile']['query_was_expanded'] is False, body['target_profile']
assert len(body['evidence']) == 0
assert body['report']['recommended_actions']
assert body['deployability']['deployment_locations'], body['deployability']
assert 'stix_bundle' in body['standards'], body['standards']
assert body['decision_gate']['label'] in {'GO', 'GO WITH CONTROLS', 'NO-GO'}, body['decision_gate']

bare = dict(valid_body, query='c2-training.example.mil')
res = client.post('/api/investigate', headers=headers, json=bare)
assert res.status_code == 200, res.text
body = res.json()
assert body['mission_context']['mission_type'] == 'joint_training', body['mission_context']
assert body['target_profile']['query_was_expanded'] is True, body['target_profile']
assert body['query'].startswith('c2-training.example.mil 연합훈련 전'), body['query']
assert [p['module'] for p in body['plan']] == ['CL', 'CB', 'CDS', 'LM', 'GM', 'RM', 'TT'], body['plan']
norm = normalize_query('defense-supplier.co.kr 관련 조사')
assert norm.default_mission_applied is True and norm.query.startswith('defense-supplier.co.kr 연합훈련 전'), norm

assert not has_investigable_target('hello')
invalid_target = dict(valid_body, query='hello')
res = client.post('/api/investigate', headers=headers, json=invalid_target)
assert res.status_code == 422, res.text
assert 'domain' in str(res.json()).lower() and 'ip' in str(res.json()).lower(), res.text

oversized_query = dict(valid_body, query='defense-supplier.co.kr ' + 'A' * 2100)
assert client.post('/api/investigate', headers=headers, json=oversized_query).status_code == 422
huge_window = dict(valid_body, time_window_days=999999999999999999999)
assert client.post('/api/investigate', headers=headers, json=huge_window).status_code == 422
bad_limit = dict(valid_body, max_results_per_source=999)
assert client.post('/api/investigate', headers=headers, json=bad_limit).status_code == 422
bad_classification = dict(valid_body, classification='X' * 129)
assert client.post('/api/investigate', headers=headers, json=bad_classification).status_code == 422

old_body_limit = settings.atlas_max_request_body_bytes
settings.atlas_max_request_body_bytes = 32
large_body = b'{"query":"defense-supplier.co.kr","live":false}' + b'A' * 80
res = client.post('/api/investigate', headers={**headers, 'Content-Type': 'application/json'}, content=large_body)
assert res.status_code == 413, res.text
settings.atlas_max_request_body_bytes = old_body_limit

redacted = redact({
    'access_token': 'token-value',
    'refreshCredential': 'credential-value',
    'nested': {'client_secret': 'secret-value'},
    'email': 'operator@example.mil',
})
assert redacted['access_token'] == '<redacted>', redacted
assert redacted['refreshCredential'] == '<redacted>', redacted
assert redacted['nested']['client_secret'] == '<redacted>', redacted
assert redacted['email'] == 'ope***@example.mil', redacted

email_entities = [(e.type, e.value) for e in extract_entities('user@example.mil 유출 여부')]
assert ('email', 'user@example.mil') in email_entities, email_entities
assert ('domain', 'example.mil') in email_entities, email_entities
assert ('domain', 'xample.mil') not in email_entities, email_entities
email_norm = normalize_query('user@example.mil')
assert email_norm.default_mission_applied is True and email_norm.query.startswith('user@example.mil 연합훈련 전'), email_norm
email_body = dict(valid_body, query='user@example.mil 유출 여부')
email_res = client.post('/api/investigate', headers=headers, json=email_body)
assert email_res.status_code == 200, email_res.text
email_json = email_res.json()
assert email_json['target_profile']['kind'] == 'email', email_json['target_profile']
assert email_json['target_profile']['display'] == 'user@example.mil', email_json['target_profile']
assert email_json['mission_context']['target'] == 'user@example.mil', email_json['mission_context']
assert all(p['query'].startswith('email:user@example.mil') or p['module'] == 'TT' for p in email_json['plan']), email_json['plan']

ip_q = '8.8.8.8 외부 노출 확인'
ip_entities = extract_entities(ip_q)
assert [(e.type, e.value) for e in ip_entities if e.type == 'ip'] == [('ip', '8.8.8.8')], ip_entities
ip_plan = build_plan(ip_entities, 5, ip_q)
assert ip_plan, 'IP query should produce a plan'
assert all(step.query == 'ip:8.8.8.8' for step in ip_plan), [step.query for step in ip_plan]
assert [step.module for step in ip_plan[:2]] == ['CDS', 'LM'], [step.module for step in ip_plan]
ip_body = dict(valid_body, query=ip_q)
ip_res = client.post('/api/investigate', headers=headers, json=ip_body)
assert ip_res.status_code == 200, ip_res.text
ip_json = ip_res.json()
assert ip_json['target_profile']['kind'] == 'ip', ip_json['target_profile']
assert ip_json['target_profile']['display'] == '8.8.8.8', ip_json['target_profile']
assert all(p['query'] == 'ip:8.8.8.8' for p in ip_json['plan']), ip_json['plan']

# Direct service path remains mock-free for live=false.
svc_res = Investigator().investigate(InvestigationRequest(**valid_body))
assert svc_res.product == 'Atlas Lens'
assert len(svc_res.evidence) == 0

print('backend validation ok: auth, request bounds, target validation, email parsing, IP planning, docs lock-down, and mock-disabled path verified')
PY
cd "$ROOT/frontend"
npm install --silent
npm run build
