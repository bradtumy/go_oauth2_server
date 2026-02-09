#!/usr/bin/env bash
set -euo pipefail

# Test Token Exchange (On-Behalf-Of) Flow
# This script demonstrates RFC 8693 token exchange where an agent acts on behalf of a human

AS_BASE="${AS_BASE:-http://localhost:8080}"
CLIENT_ID="${CLIENT_ID:-agent-cli}"
CLIENT_SECRET="${CLIENT_SECRET:-agent-cli-secret}"
AGENT_ID="${AGENT_ID:-ingestor-42}"
AGENT_NAME="${AGENT_NAME:-Data Ingestor}"
HUMAN_EMAIL="${HUMAN_EMAIL:-alice@example.com}"
HUMAN_NAME="${HUMAN_NAME:-Alice Example}"
TENANT_ID="${TENANT_ID:-default}"
AUDIENCE="${AUDIENCE:-http://localhost:9090}"

echo "========================================"
echo "RFC 8693 Token Exchange (On-Behalf-Of)"
echo "========================================"
echo ""

# Step 1: Register human identity
echo "Step 1: Registering human identity..."
echo "  Email: ${HUMAN_EMAIL}"
echo "  Name:  ${HUMAN_NAME}"
echo ""

HUMAN_RESPONSE=$(curl -sS -X POST "${AS_BASE}/register/human" \
  -H 'Content-Type: application/json' \
  -d "{
    \"email\": \"${HUMAN_EMAIL}\",
    \"name\": \"${HUMAN_NAME}\",
    \"tenant_id\": \"${TENANT_ID}\"
  }")

echo "${HUMAN_RESPONSE}" | jq .
echo ""

if echo "${HUMAN_RESPONSE}" | jq -e '.human_id' > /dev/null 2>&1; then
  HUMAN_ID=$(echo "${HUMAN_RESPONSE}" | jq -r '.human_id')
  echo "✓ Human registered successfully (ID: ${HUMAN_ID})"
else
  echo "Note: Human may already be registered"
fi
echo ""

# Step 2: Register agent identity
echo "Step 2: Registering agent identity..."
echo "  Agent ID: ${AGENT_ID}"
echo "  Name:     ${AGENT_NAME}"
echo "  Client:   ${CLIENT_ID}"
echo ""

# Delete existing agent if it exists (to ensure clean state with correct capabilities)
EXISTING_AGENT=$(curl -sS "${AS_BASE}/agents" 2>/dev/null | jq -r ".items[] | select(.agent_id == \"${AGENT_ID}\") | .id" 2>/dev/null || echo "")
if [ -n "${EXISTING_AGENT}" ]; then
  echo "Deleting existing agent (ID: ${EXISTING_AGENT}) to re-register with correct capabilities..."
  curl -sS -X DELETE "${AS_BASE}/agents/${EXISTING_AGENT}" > /dev/null 2>&1 || true
fi

AGENT_RESPONSE=$(curl -sS -X POST "${AS_BASE}/register/agent" \
  -H 'Content-Type: application/json' \
  -d "{
    \"agent_id\": \"${AGENT_ID}\",
    \"name\": \"${AGENT_NAME}\",
    \"client_id\": \"${CLIENT_ID}\",
    \"capabilities\": [\"orders:export\"],
    \"tenant_id\": \"${TENANT_ID}\"
  }")

echo "${AGENT_RESPONSE}" | jq .
echo ""

if echo "${AGENT_RESPONSE}" | jq -e '.agent_id' > /dev/null 2>&1; then
  echo "✓ Agent registered successfully"
else
  echo "Note: Agent may already be registered"
fi
echo ""

# Step 3: Mint subject assertion for the human
echo "Step 3: Minting subject assertion for ${HUMAN_EMAIL}..."
echo ""

SUBJECT_RESPONSE=$(curl -sS -X POST "${AS_BASE}/subject-assertion" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"${HUMAN_EMAIL}\"}")

echo "${SUBJECT_RESPONSE}" | jq .
echo ""

if echo "${SUBJECT_RESPONSE}" | jq -e '.assertion' > /dev/null 2>&1; then
  SUBJECT_TOKEN=$(echo "${SUBJECT_RESPONSE}" | jq -r '.assertion')
  echo "✓ Subject assertion obtained"
else
  echo "✗ Failed to obtain subject assertion"
  exit 1
fi
echo ""

# Step 4: Perform token exchange with authorization details
echo "Step 4: Performing token exchange (agent acting on behalf of human)..."
echo "  Subject:  ${HUMAN_EMAIL}"
echo "  Actor:    ${AGENT_ID}"
echo "  Audience: ${AUDIENCE}"
echo ""

OBO_RESPONSE=$(curl -sS -X POST "${AS_BASE}/oauth2/token" \
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
    "constraints": {"resource_ids": ["acct:abc"]}
  }]')

echo "${OBO_RESPONSE}" | jq .

if echo "${OBO_RESPONSE}" | jq -e '.access_token' > /dev/null 2>&1; then
  echo ""
  echo "✓ OBO access token obtained successfully!"
  echo ""
  
  OBO_TOKEN=$(echo "${OBO_RESPONSE}" | jq -r '.access_token')
  
  echo "Decoding OBO JWT payload..."
  echo ""
  
  # Decode JWT payload (second part of the token)
  PAYLOAD=$(echo "${OBO_TOKEN}" | cut -d. -f2)
  # Add padding if needed
  case $((${#PAYLOAD} % 4)) in
    2) PAYLOAD="${PAYLOAD}==" ;;
    3) PAYLOAD="${PAYLOAD}=" ;;
  esac
  
  DECODED=$(echo "${PAYLOAD}" | base64 -d 2>/dev/null)
  echo "${DECODED}" | jq .
  
  echo ""
  echo "Key claims:"
  echo "  sub (human):    $(echo "${DECODED}" | jq -r '.sub // "N/A"')"
  echo "  act.actor (agent): $(echo "${DECODED}" | jq -r '.act.actor // "N/A"')"
  echo "  perm (hash):    $(echo "${DECODED}" | jq -r '.perm // "N/A"')"
  echo "  aud (audience): $(echo "${DECODED}" | jq -r '.aud // "N/A"')"
  
  echo ""
  echo "✓ OBO token obtained and saved!"
  echo ""
  echo "To use the token, export it to your environment:"
  echo "  export OBO_TOKEN='${OBO_TOKEN}'"
  echo ""
  echo "Then call the resource server:"
  echo "  ./scripts/test_resource_server.sh"
  echo ""
  echo "Or run both in one command:"
  echo "  OBO_TOKEN='${OBO_TOKEN}' ./scripts/test_resource_server.sh"
else
  echo ""
  echo "✗ Failed to obtain OBO token"
  exit 1
fi
