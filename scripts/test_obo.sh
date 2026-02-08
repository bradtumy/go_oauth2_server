#!/usr/bin/env bash
set -euo pipefail

AS_BASE=${AS_BASE:-http://localhost:8080}
RS_BASE=${RS_BASE:-http://localhost:9090}
HUMAN_CLIENT_ID=${HUMAN_CLIENT_ID:-human-web}
AGENT_CLIENT_ID=${AGENT_CLIENT_ID:-agent-cli}
AGENT_CLIENT_SECRET=${AGENT_CLIENT_SECRET:-agent-cli-secret}
REDIRECT_URI=${REDIRECT_URI:-http://localhost:5555/callback}
USER_ID=${USER_ID:-user:123}
ACCOUNT_ID=${ACCOUNT_ID:-acct:abc}

printf "[1/4] Requesting authorization code...\n" >&2
AUTH_RES=$(curl -si -G "${AS_BASE}/oauth2/authorize" \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=${HUMAN_CLIENT_ID}" \
  --data-urlencode "redirect_uri=${REDIRECT_URI}" \
  --data-urlencode "scope=tickets.read" \
  --data-urlencode "human_id=${USER_ID}" \
  --data-urlencode "state=test")
CODE=$(AUTH_RES="$AUTH_RES" python - <<'PY'
import os
import sys
import urllib.parse

text = os.environ.get('AUTH_RES', '')
for line in text.splitlines():
    if line.lower().startswith('location:'):
        loc = line.split(':', 1)[1].strip()
        parsed = urllib.parse.urlparse(loc)
        qs = urllib.parse.parse_qs(parsed.query)
        code = qs.get('code', [''])[0]
        if code:
            print(code)
            break
else:
    sys.exit('authorization code not found')
PY
)

printf "[2/4] Exchanging code for user token...\n" >&2
TOKEN_JSON=$(curl -s -X POST "${AS_BASE}/oauth2/token" \
  -u "${HUMAN_CLIENT_ID}:" \
  -d "grant_type=authorization_code" \
  --data-urlencode "code=${CODE}" \
  --data-urlencode "redirect_uri=${REDIRECT_URI}")
USER_TOKEN=$(printf '%s' "$TOKEN_JSON" | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

printf "[3/4] Minting actor assertion and performing token exchange...\n" >&2
ACTOR_ASSERTION=$(go run ./tools/mint_assertion -actor agent:ingestor-42 -client "${AGENT_CLIENT_ID}")
RAR='[{"type":"agent-action","locations":["'"${RS_BASE}"'"],"actions":["orders:export"],"constraints":{"resource_ids":["'"${ACCOUNT_ID}"'"],"time_limit_sec":900,"max_records":1000,"purpose":"customer_export"}}]'
OBO_JSON=$(curl -s -X POST "${AS_BASE}/oauth2/token" \
  -u "${AGENT_CLIENT_ID}:${AGENT_CLIENT_SECRET}" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  --data-urlencode "subject_token=${USER_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  --data-urlencode "actor_token=${ACTOR_ASSERTION}" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:jwt" \
  --data-urlencode "audience=${RS_BASE}" \
  --data-urlencode "authorization_details=${RAR}")
OBO_TOKEN=$(printf '%s' "$OBO_JSON" | python -c "import json,sys; print(json.load(sys.stdin)['access_token'])")

printf "[4/4] Calling resource server...\n" >&2
RS_RES=$(curl -s -H "Authorization: Bearer ${OBO_TOKEN}" "${RS_BASE}/accounts/${ACCOUNT_ID}/orders/export")
STATUS=$(printf '%s' "$RS_RES" | python -c "import json,sys; print(json.load(sys.stdin)['status'])")
if [[ "$STATUS" != "ok" ]]; then
  echo "Resource server response: $RS_RES" >&2
  exit 1
fi

printf '{"authorization_code":"%s","user_token_response":%s,"obo_token_response":%s,"resource_response":%s}\n' \
  "$CODE" "$TOKEN_JSON" "$OBO_JSON" "$RS_RES"
