#!/bin/bash
# Test script for OAuth authentication flow

set -e

BASE_URL="http://localhost:8080"
CLIENT_ID="human-web"
REDIRECT_URI="http://localhost:5555/callback"
SCOPE="tickets.read"

# Generate PKCE challenge
CODE_VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CODE_CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
STATE="random123"

echo "=== OAuth 2.0 Authorization Code with PKCE Flow Test ==="
echo ""

# Step 1: Register a test user
echo "Step 1: Registering test user..."
USER_RESPONSE=$(curl -s -X POST "$BASE_URL/register/human" \
  -H 'Content-Type: application/json' \
  -d "{
    \"email\": \"flowtest@example.com\",
    \"name\": \"Flow Test User\",
    \"password\": \"TestPassword123\",
    \"tenant_id\": \"default\"
  }")

if echo "$USER_RESPONSE" | grep -q "already registered"; then
  echo "User already exists, continuing..."
else
  echo "User registered: $(echo $USER_RESPONSE | jq -r '.email')"
fi
echo ""

# Step 2: Attempt to access authorize endpoint (should redirect to login)
echo "Step 2: Accessing /oauth2/authorize without authentication..."
AUTH_URL="$BASE_URL/oauth2/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=$SCOPE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256&state=$STATE"

RESPONSE=$(curl -s -i "$AUTH_URL")
if echo "$RESPONSE" | grep -q "Location:.*login"; then
  echo "✓ Correctly redirected to login page"
else
  echo "✗ Expected redirect to login"
  exit 1
fi
echo ""

# Step 3: Login with credentials
echo "Step 3: Logging in with credentials..."
LOGIN_RESPONSE=$(curl -s -i -c /tmp/flow_cookies.txt -X POST "$BASE_URL/login" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "email=flowtest@example.com" \
  -d "password=TestPassword123" \
  -d "return_to=/")

if echo "$LOGIN_RESPONSE" | grep -q "Set-Cookie: session_id="; then
  SESSION_ID=$(echo "$LOGIN_RESPONSE" | grep "Set-Cookie: session_id=" | sed 's/.*session_id=\([^;]*\).*/\1/')
  echo "✓ Login successful, session created: ${SESSION_ID:0:20}..."
else
  echo "✗ Login failed"
  exit 1
fi
echo ""

# Step 4: Access authorize endpoint with session (should show consent)
echo "Step 4: Accessing /oauth2/authorize with authentication..."
CONSENT_PAGE=$(curl -s -b /tmp/flow_cookies.txt "$AUTH_URL")

if echo "$CONSENT_PAGE" | grep -q "Authorize"; then
  echo "✓ Consent page displayed successfully"
else
  echo "✗ Expected consent page"
  exit 1
fi
echo ""

# Step 5: Approve consent
echo "Step 5: Approving authorization request..."
CONSENT_RESPONSE=$(curl -s -i -b /tmp/flow_cookies.txt -X POST "$BASE_URL/consent" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "action=approve" \
  -d "client_id=$CLIENT_ID" \
  -d "redirect_uri=$REDIRECT_URI" \
  -d "scope=$SCOPE" \
  -d "state=$STATE" \
  -d "code_challenge=$CODE_CHALLENGE" \
  -d "code_challenge_method=S256")

if echo "$CONSENT_RESPONSE" | grep -q "Location:.*code="; then
  CODE=$(echo "$CONSENT_RESPONSE" | grep "Location:" | sed 's/.*code=\([^&]*\).*/\1/')
  echo "✓ Authorization code issued: ${CODE:0:20}..."
else
  echo "✗ Expected authorization code"
  exit 1
fi
echo ""

# Step 6: Exchange code for token
echo "Step 6: Exchanging authorization code for access token..."
TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/oauth2/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "grant_type=authorization_code" \
  -d "code=$CODE" \
  -d "client_id=$CLIENT_ID" \
  -d "code_verifier=$CODE_VERIFIER" \
  -d "redirect_uri=$REDIRECT_URI")

if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
  ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')
  echo "✓ Access token obtained: ${ACCESS_TOKEN:0:40}..."
  echo ""
  echo "Full token response:"
  echo "$TOKEN_RESPONSE" | jq .
else
  echo "✗ Token exchange failed"
  echo "$TOKEN_RESPONSE"
  exit 1
fi
echo ""

echo "=== ✅ All authentication flow tests passed! ==="
echo ""
echo "Summary:"
echo "- User registration with password ✓"
echo "- Authentication required for /oauth2/authorize ✓"
echo "- Login with credentials ✓"
echo "- Session management with cookies ✓"
echo "- Consent page displayed ✓"
echo "- Authorization code issued ✓"
echo "- Token exchange successful ✓"
echo ""
echo "The OAuth 2.0 authorization code with PKCE flow is fully functional!"

# Cleanup
rm -f /tmp/flow_cookies.txt
