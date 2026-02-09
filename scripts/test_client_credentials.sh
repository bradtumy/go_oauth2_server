#!/usr/bin/env bash
set -euo pipefail

# Test Client Credentials Flow
# This script demonstrates the OAuth2 client credentials grant for machine-to-machine authentication

AS_BASE="${AS_BASE:-http://localhost:8080}"
CLIENT_ID="${CLIENT_ID:-agent-cli}"
CLIENT_SECRET="${CLIENT_SECRET:-agent-cli-secret}"
SCOPE="${SCOPE:-tickets.read}"

echo "========================================"
echo "OAuth2 Client Credentials Grant"
echo "========================================"
echo ""
echo "Configuration:"
echo "  AS Base:       ${AS_BASE}"
echo "  Client ID:     ${CLIENT_ID}"
echo "  Client Secret: ${CLIENT_SECRET}"
echo "  Scope:         ${SCOPE}"
echo ""

echo "Requesting access token..."
echo ""

RESPONSE=$(curl -sS -X POST "${AS_BASE}/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "scope=${SCOPE}")

echo "${RESPONSE}" | jq .

if echo "${RESPONSE}" | jq -e '.access_token' > /dev/null 2>&1; then
  echo ""
  echo "✓ Access token obtained successfully!"
  echo ""
  
  ACCESS_TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token')
  echo "Decoding JWT payload..."
  echo ""
  
  # Decode JWT payload (second part of the token)
  PAYLOAD=$(echo "${ACCESS_TOKEN}" | cut -d. -f2)
  # Add padding if needed
  case $((${#PAYLOAD} % 4)) in
    2) PAYLOAD="${PAYLOAD}==" ;;
    3) PAYLOAD="${PAYLOAD}=" ;;
  esac
  echo "${PAYLOAD}" | base64 -d 2>/dev/null | jq . || echo "Failed to decode JWT"
  
  echo ""
  echo "Token saved to environment variable ACCESS_TOKEN"
  echo "Use it in API calls: curl -H \"Authorization: Bearer \${ACCESS_TOKEN}\" ..."
else
  echo ""
  echo "✗ Failed to obtain access token"
  exit 1
fi
