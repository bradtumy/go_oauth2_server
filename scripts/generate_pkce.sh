#!/usr/bin/env bash
# Generate PKCE parameters for OAuth2 authorization code flow
# Usage: source ./scripts/generate_pkce.sh

CODE_VERIFIER=$(openssl rand -base64 43 | tr -d '=+/' | head -c 43)
CODE_CHALLENGE=$(printf '%s' "${CODE_VERIFIER}" | openssl dgst -sha256 -binary | \
  openssl base64 -A | tr '+/' '-_' | tr -d '=')

echo "✓ PKCE parameters generated:"
echo ""
echo "CODE_VERIFIER:  ${CODE_VERIFIER}"
echo "CODE_CHALLENGE: ${CODE_CHALLENGE}"
echo ""
echo "These variables are now set in your current shell session."

export CODE_VERIFIER
export CODE_CHALLENGE
