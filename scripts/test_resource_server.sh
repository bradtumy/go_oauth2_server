#!/usr/bin/env bash
set -euo pipefail

# Test Resource Server Access with OBO Token
# This script demonstrates calling a protected resource with an OBO token

RS_BASE="${RS_BASE:-http://localhost:9090}"
ACCOUNT_ID="${ACCOUNT_ID:-acct:abc}"

echo "========================================"
echo "Resource Server Access Test"
echo "========================================"
echo ""

# Check if OBO_TOKEN is set
if [ -z "${OBO_TOKEN:-}" ]; then
  echo "Error: OBO_TOKEN environment variable not set"
  echo ""
  echo "Please run the token exchange flow first to obtain an OBO token:"
  echo "  ./scripts/test_token_exchange.sh"
  echo ""
  echo "Or set the token manually:"
  echo "  export OBO_TOKEN='your_obo_token_here'"
  exit 1
fi

echo "Configuration:"
echo "  RS Base:    ${RS_BASE}"
echo "  Account ID: ${ACCOUNT_ID}"
echo "  Token:      ${OBO_TOKEN:0:20}..."
echo ""

# Test the orders export endpoint
ENDPOINT="${RS_BASE}/accounts/${ACCOUNT_ID}/orders/export"

echo "Calling protected resource..."
echo "  GET ${ENDPOINT}"
echo ""

RESPONSE=$(curl -sS -w "\nHTTP_STATUS:%{http_code}" \
  -H "Authorization: Bearer ${OBO_TOKEN}" \
  "${ENDPOINT}")

HTTP_STATUS=$(echo "${RESPONSE}" | grep "HTTP_STATUS:" | cut -d: -f2)
BODY=$(echo "${RESPONSE}" | sed '/HTTP_STATUS:/d')

if [ "${HTTP_STATUS}" = "200" ]; then
  echo "✓ Success! Resource server response:"
  echo ""
  echo "${BODY}" | jq . 2>/dev/null || echo "${BODY}"
  echo ""
  echo "The OBO token was successfully validated by the resource server."
  echo "The resource server verified:"
  echo "  - JWT signature"
  echo "  - Token audience"
  echo "  - Human subject (sub)"
  echo "  - Agent actor (act.actor)"
  echo "  - Granted authorization_details"
  echo "  - Authorization details"
elif [ "${HTTP_STATUS}" = "401" ]; then
  echo "✗ Unauthorized (401)"
  echo ""
  echo "${BODY}" | jq . 2>/dev/null || echo "${BODY}"
  echo ""
  echo "Possible issues:"
  echo "  - Token has expired"
  echo "  - Invalid signature"
  echo "  - Wrong audience"
elif [ "${HTTP_STATUS}" = "403" ]; then
  echo "✗ Forbidden (403)"
  echo ""
  echo "${BODY}" | jq . 2>/dev/null || echo "${BODY}"
  echo ""
  echo "Possible issues:"
  echo "  - Insufficient permissions"
  echo "  - Authorization-detail type, action, or resource mismatch"
  echo "  - Authorization details don't match the resource"
else
  echo "✗ Request failed with status ${HTTP_STATUS}"
  echo ""
  echo "${BODY}" | jq . 2>/dev/null || echo "${BODY}"
fi
