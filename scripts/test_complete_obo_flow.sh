#!/usr/bin/env bash
set -euo pipefail

# Complete OBO Flow: Token Exchange + Resource Server Access
# This script runs the complete flow from identity registration to resource access

AS_BASE="${AS_BASE:-http://localhost:8080}"
RS_BASE="${RS_BASE:-http://localhost:9090}"
CLIENT_ID="${CLIENT_ID:-agent-cli}"
CLIENT_SECRET="${CLIENT_SECRET:-agent-cli-secret}"
AGENT_ID="${AGENT_ID:-ingestor-42}"
HUMAN_EMAIL="${HUMAN_EMAIL:-alice@example.com}"
ACCOUNT_ID="${ACCOUNT_ID:-acct:abc}"

echo "========================================"
echo "Complete OBO Flow Test"
echo "========================================"
echo ""

# Step 1: Run token exchange to get OBO token
echo "Running token exchange flow..."
echo ""

# Source the token exchange script to get OBO_TOKEN in this shell
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Run token exchange inline to capture OBO_TOKEN
TENANT_ID="default"
AGENT_NAME="Data Ingestor"
HUMAN_NAME="Alice Example"
AUDIENCE="${RS_BASE}"

# Register human
curl -sS -X POST "${AS_BASE}/register/human" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"${HUMAN_EMAIL}\",\"name\":\"${HUMAN_NAME}\",\"tenant_id\":\"${TENANT_ID}\"}" \
  > /dev/null 2>&1 || true

# Delete and re-register agent
EXISTING_AGENT=$(curl -sS "${AS_BASE}/agents" 2>/dev/null | jq -r ".items[] | select(.agent_id == \"${AGENT_ID}\") | .id" 2>/dev/null || echo "")
if [ -n "${EXISTING_AGENT}" ]; then
  curl -sS -X DELETE "${AS_BASE}/agents/${EXISTING_AGENT}" > /dev/null 2>&1 || true
fi

curl -sS -X POST "${AS_BASE}/register/agent" \
  -H 'Content-Type: application/json' \
  -d "{
    \"agent_id\": \"${AGENT_ID}\",
    \"name\": \"${AGENT_NAME}\",
    \"client_id\": \"${CLIENT_ID}\",
    \"capabilities\": [\"orders:export\"],
    \"tenant_id\": \"${TENANT_ID}\"
  }" > /dev/null

# Get subject assertion
SUBJECT_TOKEN=$(curl -sS -X POST "${AS_BASE}/subject-assertion" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"${HUMAN_EMAIL}\"}" | jq -r '.assertion')

# Perform token exchange
OBO_TOKEN=$(curl -sS -X POST "${AS_BASE}/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d "subject_token=${SUBJECT_TOKEN}" \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  -d "audience=${AUDIENCE}" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  --data-urlencode 'authorization_details=[{
    "type": "agent-action",
    "actions": ["orders:export"],
    "constraints": {"resource_ids": ["'${ACCOUNT_ID}'"]}
  }]' | jq -r '.access_token')

if [ -z "${OBO_TOKEN}" ] || [ "${OBO_TOKEN}" = "null" ]; then
  echo "✗ Failed to obtain OBO token"
  exit 1
fi

echo "✓ OBO token obtained"
echo ""

# Step 2: Call resource server
echo "Calling resource server..."
ENDPOINT="${RS_BASE}/accounts/${ACCOUNT_ID}/orders/export"
echo "  GET ${ENDPOINT}"
echo ""

RESPONSE=$(curl -sS -w "\nHTTP_STATUS:%{http_code}" \
  -H "Authorization: Bearer ${OBO_TOKEN}" \
  "${ENDPOINT}")

HTTP_STATUS=$(echo "${RESPONSE}" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "${RESPONSE}" | sed '/HTTP_STATUS:/d')

echo "Response:"
echo "${BODY}" | jq . 2>/dev/null || echo "${BODY}"
echo ""

if [ "${HTTP_STATUS}" = "200" ]; then
  echo "✓ Complete OBO flow successful!"
  echo ""
  echo "Flow summary:"
  echo "  1. Registered human: ${HUMAN_EMAIL}"
  echo "  2. Registered agent: ${AGENT_ID}"
  echo "  3. Obtained subject assertion"
  echo "  4. Exchanged for OBO token (agent acting on behalf of human)"
  echo "  5. Called resource server with OBO token"
  echo ""
  echo "The resource server verified:"
  echo "  - JWT signature and claims"
  echo "  - Human subject: ${HUMAN_EMAIL}"
  echo "  - Agent actor: ${AGENT_ID}"
  echo "  - Permissions and authorization details"
else
  echo "✗ Resource server call failed with status ${HTTP_STATUS}"
  exit 1
fi
