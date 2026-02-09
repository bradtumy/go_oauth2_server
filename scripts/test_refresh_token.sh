#!/usr/bin/env bash
set -euo pipefail

# Test Refresh Token Flow
# This script demonstrates the OAuth2 refresh token grant
# Note: You need a valid refresh token from an authorization code flow first

AS_BASE="${AS_BASE:-http://localhost:8080}"
CLIENT_ID="${CLIENT_ID:-human-web}"

echo "========================================"
echo "OAuth2 Refresh Token Grant"
echo "========================================"
echo ""

# Check if REFRESH_TOKEN is already set
if [ -z "${REFRESH_TOKEN:-}" ]; then
  echo "No refresh token found in environment."
  echo ""
  echo "To obtain a refresh token, run the authorization code flow first:"
  echo "  ./scripts/test_auth_code_flow.sh"
  echo ""
  echo "Then extract the refresh_token from the response and either:"
  echo "  1. Set it as an environment variable: export REFRESH_TOKEN='your_token'"
  echo "  2. Or paste it below when prompted"
  echo ""
  read -p "Refresh token: " REFRESH_TOKEN
  
  if [ -z "${REFRESH_TOKEN}" ]; then
    echo "Error: No refresh token provided"
    exit 1
  fi
fi

echo "Configuration:"
echo "  AS Base:   ${AS_BASE}"
echo "  Client ID: ${CLIENT_ID}"
echo "  Token:     ${REFRESH_TOKEN:0:20}..."
echo ""

echo "Exchanging refresh token for new access token..."
echo ""

RESPONSE=$(curl -sS -X POST "${AS_BASE}/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d "refresh_token=${REFRESH_TOKEN}" \
  -d "client_id=${CLIENT_ID}")

echo "${RESPONSE}" | jq .

if echo "${RESPONSE}" | jq -e '.access_token' > /dev/null 2>&1; then
  echo ""
  echo "✓ New access token obtained successfully!"
  echo ""
  
  ACCESS_TOKEN=$(echo "${RESPONSE}" | jq -r '.access_token')
  NEW_REFRESH_TOKEN=$(echo "${RESPONSE}" | jq -r '.refresh_token // empty')
  
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
  echo "New access token saved to: ACCESS_TOKEN"
  
  if [ -n "${NEW_REFRESH_TOKEN}" ]; then
    echo "New refresh token saved to: REFRESH_TOKEN"
    echo ""
    echo "You can run this script again to refresh the token:"
    echo "  REFRESH_TOKEN='${NEW_REFRESH_TOKEN}' ./scripts/test_refresh_token.sh"
  fi
else
  echo ""
  echo "✗ Failed to refresh token"
  exit 1
fi
