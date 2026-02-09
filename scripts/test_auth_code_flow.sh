#!/usr/bin/env bash
set -euo pipefail

# Test Authorization Code Flow with PKCE
# This script demonstrates the complete OAuth2 authorization code flow

AS_BASE="${AS_BASE:-http://localhost:8080}"
EMAIL="${EMAIL:-alice@example.com}"
CLIENT_ID="human-web"
REDIRECT_URI="http://localhost:5555/callback"
SCOPE="tickets.read"

echo "========================================"
echo "OAuth2 Authorization Code Flow with PKCE"
echo "========================================"
echo ""

# Step 1: Register human (if not already registered)
echo "Step 1: Registering human identity..."
curl -sS -X POST "${AS_BASE}/register/human" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"${EMAIL}\",\"name\":\"Alice Example\",\"tenant_id\":\"default\"}" \
  > /dev/null 2>&1 || true
echo "✓ Human registered (or already exists)"
echo ""

# Step 2: Generate PKCE parameters
echo "Step 2: Generating PKCE parameters..."
CODE_VERIFIER=$(openssl rand -base64 43 | tr -d '=+/' | head -c 43)
CODE_CHALLENGE=$(printf '%s' "${CODE_VERIFIER}" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

echo "  CODE_VERIFIER:  ${CODE_VERIFIER}"
echo "  CODE_CHALLENGE: ${CODE_CHALLENGE}"
echo ""

# Step 3: Build authorization URL
AUTH_URL="${AS_BASE}/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=${SCOPE}&email=${EMAIL}&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

echo "Step 3: Opening browser for authorization..."
echo "  URL: ${AUTH_URL}"
echo ""
open "${AUTH_URL}"

echo "After the browser redirects, you'll see a URL like:"
echo "  http://localhost:5555/callback?code=XXXXXXXX"
echo ""
echo "Copy the code from the URL and paste it below:"
read -p "Authorization code: " AUTH_CODE

if [ -z "${AUTH_CODE}" ]; then
  echo "Error: No authorization code provided"
  exit 1
fi

echo ""
echo "Step 4: Exchanging authorization code for tokens..."
echo ""

curl -sS -X POST "${AS_BASE}/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d "code=${AUTH_CODE}" \
  -d "client_id=${CLIENT_ID}" \
  -d "code_verifier=${CODE_VERIFIER}" \
  -d "redirect_uri=${REDIRECT_URI}" | jq .

echo ""
echo "✓ Authorization code flow complete!"
