#!/bin/bash
# Quick demo of RFC 7523 JWT Bearer Client Assertion authentication

set -e

echo "RFC 7523 Quick Demo"
echo "==================="
echo ""

# Configuration
AS_URL="${AS_URL:-http://localhost:8080}"
ADMIN_TOKEN="${AS_ADMIN_TOKEN:-dev-admin-token}"
CLIENT_ID="demo-agent"

# Create temp directory
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

cd "$TEMP_DIR"

echo "1. Generating RSA-2048 keypair..."
~/dev/tokenator/tools/mint_rfc7523_assertion/mint_rfc7523_assertion -generate-keypair
echo ""

echo "2. Registering client with public key..."
PUBLIC_KEY=$(cat agent-public-key.pem)
curl -s -X POST "$AS_URL/admin/clients" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
        \"client_id\": \"$CLIENT_ID\",
        \"client_type\": \"confidential\",
        \"public_key\": \"$PUBLIC_KEY\",
        \"key_algorithm\": \"RS256\",
        \"grant_types\": [\"client_credentials\"],
        \"scopes\": [\"tickets.read\"]
    }" | jq '.'
echo ""

echo "3. Generating JWT assertion..."
ASSERTION=$(~/dev/tokenator/tools/mint_rfc7523_assertion/mint_rfc7523_assertion \
    -client-id "$CLIENT_ID" \
    -private-key agent-private-key.pem \
    -audience "$AS_URL/token")
echo "Assertion: ${ASSERTION:0:80}..."
echo ""

echo "4. Requesting access token..."
curl -s -X POST "$AS_URL/token" \
    -d "grant_type=client_credentials" \
    -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
    -d "client_assertion=$ASSERTION" \
    -d "scope=tickets.read" | jq '.'
echo ""

echo "5. Cleaning up..."
curl -s -X DELETE "$AS_URL/admin/clients/$CLIENT_ID" \
    -H "Authorization: Bearer $ADMIN_TOKEN"
echo "Done!"
