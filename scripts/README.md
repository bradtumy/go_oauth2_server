# Test Scripts

This directory contains a suite of test scripts for validating OAuth 2.0 flows in the tokenator project. These scripts demonstrate all supported authentication and authorization patterns and can be used for testing, development, and learning.

## Quick Start

**Most users should start with the bundled end-to-end scripts:**

```bash
# Complete OBO flow (identity registration → token exchange → resource access)
./scripts/test_complete_obo_flow.sh

# Authorization code flow with PKCE (interactive, opens browser)
./scripts/test_auth_code_flow.sh

# Client credentials flow (machine-to-machine)
./scripts/test_client_credentials.sh
```

## Prerequisites

Before running these scripts, ensure:

1. **Services are running** - Either via Docker Compose or locally:
   ```bash
   # Option 1: Docker (recommended)
   docker compose up -d
   
   # Option 2: Local development
   go run ./cmd/as &    # Authorization Server on :8080
   go run ./cmd/rs &    # Resource Server on :9090
   ```

2. **OAuth clients are seeded**:
   ```bash
   make seed
   ```

3. **Required tools installed**: `curl`, `jq`, `openssl`

## End-to-End Scripts

These scripts perform complete flows from start to finish, ideal for testing and demonstrations.

### `test_complete_obo_flow.sh`

**What it does:** Demonstrates the complete RFC 8693 token exchange (on-behalf-of) flow where an agent acts on behalf of a human user.

**Flow:**
1. Registers a human identity (Alice)
2. Registers an agent identity (Data Ingestor)
3. Mints a subject assertion for the human
4. Performs token exchange to get an OBO token
5. Calls the resource server with the OBO token
6. Validates the response

**When to use:**
- Testing the complete OBO delegation pattern
- Demonstrating agent-on-behalf-of-human scenarios
- Validating end-to-end token exchange and resource access
- CI/CD smoke tests

**Configuration:**
```bash
AS_BASE=http://localhost:8080 \
RS_BASE=http://localhost:9090 \
HUMAN_EMAIL=alice@example.com \
AGENT_ID=ingestor-42 \
./scripts/test_complete_obo_flow.sh
```

### `test_auth_code_flow.sh`

**What it does:** Demonstrates the OAuth 2.0 authorization code flow with PKCE for user authentication.

**Flow:**
1. Registers a human identity
2. Generates PKCE parameters (code verifier and challenge)
3. Opens browser to authorization endpoint
4. Prompts user to paste the authorization code from redirect URL
5. Exchanges code for access and refresh tokens
6. Displays decoded JWT claims

**When to use:**
- Testing user authentication flows
- Validating PKCE implementation
- Understanding authorization code grant mechanics
- Demonstrating public client authentication

**Interactive:** This script opens a browser and requires manual input of the authorization code.

**Configuration:**
```bash
AS_BASE=http://localhost:8080 \
HUMAN_EMAIL=alice@example.com \
./scripts/test_auth_code_flow.sh
```

## Individual Flow Scripts

These scripts test specific OAuth 2.0 grant types independently.

### `test_client_credentials.sh`

**What it does:** Tests the client credentials grant for machine-to-machine authentication.

**Use case:** Service-to-service authentication without user context.

**When to use:**
- Testing confidential client authentication
- Validating client credentials grant
- Backend service authentication scenarios
- API key equivalent workflows

**Configuration:**
```bash
CLIENT_ID=agent-cli \
CLIENT_SECRET=agent-cli-secret \
SCOPE=tickets.read \
./scripts/test_client_credentials.sh
```

**Output:** Access token with client identity and requested scopes.

### `test_refresh_token.sh`

**What it does:** Exchanges a refresh token for a new access token.

**When to use:**
- Testing refresh token rotation
- Validating token refresh mechanics
- After running authorization code flow to refresh the token

**Prerequisites:** Requires a valid refresh token from an authorization code flow.

**Usage:**
```bash
# Get refresh token from auth code flow first
./scripts/test_auth_code_flow.sh
# Copy the refresh_token from output

# Then use it
REFRESH_TOKEN='your_refresh_token_here' ./scripts/test_refresh_token.sh
```

**Note:** Refresh token rotation is enabled - each refresh generates a new refresh token and invalidates the old one.

### `test_token_exchange.sh`

**What it does:** Performs RFC 8693 token exchange to obtain an OBO token.

**Flow:**
1. Registers human and agent identities
2. Mints a subject assertion
3. Exchanges assertion for OBO token with authorization details
4. Displays token claims and usage instructions

**When to use:**
- Testing token exchange in isolation (without resource server call)
- Debugging OBO token generation
- Validating authorization_details handling
- Examining OBO token structure

**Output:** Provides instructions to export the OBO token and call the resource server separately.

**Configuration:**
```bash
HUMAN_EMAIL=alice@example.com \
AGENT_ID=my-agent \
./scripts/test_token_exchange.sh
```

### `test_resource_server.sh`

**What it does:** Calls a protected resource with an OBO token.

**Prerequisites:** Requires `OBO_TOKEN` environment variable set.

**When to use:**
- Testing resource server token validation
- Validating permission enforcement
- After obtaining an OBO token from `test_token_exchange.sh`

**Usage:**
```bash
# After running token exchange
export OBO_TOKEN='your_token_here'
./scripts/test_resource_server.sh

# Or inline
OBO_TOKEN='your_token_here' ./scripts/test_resource_server.sh
```

**Configuration:**
```bash
RS_BASE=http://localhost:9090 \
ACCOUNT_ID=acct:abc \
OBO_TOKEN='...' \
./scripts/test_resource_server.sh
```

## Utility Scripts

### `generate_pkce.sh`

**What it does:** Generates PKCE parameters and exports them to the current shell.

**When to use:**
- Manual authorization code flow testing
- Generating PKCE parameters for custom requests

**Usage:**
```bash
# Must be sourced, not executed
source ./scripts/generate_pkce.sh
# or
. ./scripts/generate_pkce.sh

# Then use the variables
echo $CODE_VERIFIER
echo $CODE_CHALLENGE
```

**Note:** This must be sourced (not executed) so variables are set in your current shell.

### `seed_clients.sh`

**What it does:** Seeds OAuth client registrations from `clients/*.json` into the database.

**When to use:**
- Initial setup
- After clearing the database
- When adding new client configurations

**Usage:**
```bash
./scripts/seed_clients.sh
# or via Makefile
make seed
```

## Common Workflows

### Testing the Complete Stack

```bash
# 1. Start services
docker compose up -d

# 2. Seed clients
make seed

# 3. Run end-to-end test
./scripts/test_complete_obo_flow.sh
```

### Manual Authorization Code Flow

```bash
# 1. Generate PKCE parameters
source ./scripts/generate_pkce.sh

# 2. Build authorization URL
open "http://localhost:8080/oauth2/authorize?response_type=code&client_id=human-web&redirect_uri=http://localhost:5555/callback&scope=tickets.read&email=alice@example.com&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

# 3. Copy code from URL and exchange
curl -X POST http://localhost:8080/oauth2/token \
  -d 'grant_type=authorization_code' \
  -d "code=YOUR_CODE" \
  -d 'client_id=human-web' \
  -d "code_verifier=${CODE_VERIFIER}" \
  -d 'redirect_uri=http://localhost:5555/callback' | jq .
```

### Testing Token Exchange + Resource Access Separately

```bash
# 1. Get OBO token
./scripts/test_token_exchange.sh
# Copy the export command from output

# 2. Export token
export OBO_TOKEN='paste_token_here'

# 3. Call resource server
./scripts/test_resource_server.sh
```

### CI/CD Integration

```bash
#!/bin/bash
# Smoke test for CI/CD pipeline

# Start services
docker compose up -d
sleep 5

# Seed clients
make seed

# Run core flows
./scripts/test_client_credentials.sh || exit 1
./scripts/test_complete_obo_flow.sh || exit 1

echo "All tests passed!"
```

## Environment Variables

All scripts support the following environment variables for customization:

| Variable | Default | Description |
|----------|---------|-------------|
| `AS_BASE` | `http://localhost:8080` | Authorization server base URL |
| `RS_BASE` | `http://localhost:9090` | Resource server base URL |
| `CLIENT_ID` | `agent-cli` | OAuth client ID |
| `CLIENT_SECRET` | `agent-cli-secret` | OAuth client secret |
| `HUMAN_EMAIL` | `alice@example.com` | Human user email |
| `HUMAN_NAME` | `Alice Example` | Human user name |
| `AGENT_ID` | `ingestor-42` | Agent identifier |
| `AGENT_NAME` | `Data Ingestor` | Agent name |
| `TENANT_ID` | `default` | Tenant identifier |
| `ACCOUNT_ID` | `acct:abc` | Resource account ID |
| `SCOPE` | varies | OAuth scopes to request |

## Troubleshooting

### "invalid_client" or "unknown client"

**Cause:** OAuth clients not seeded in database.

**Solution:**
```bash
make seed
```

### "invalid_scope" or "scope not allowed"

**Cause:** Requested scope doesn't match client configuration.

**Solution:** Check `clients/*.json` for allowed scopes. Default scopes:
- `agent-cli`: `tickets.read`, `tickets.write`, `refunds.create`
- `human-web`: `tickets.read`

### "invalid code_verifier" or PKCE errors

**Cause:** Code verifier too short (< 43 characters) or doesn't match challenge.

**Solution:** Use the provided `generate_pkce.sh` script which generates RFC 7636-compliant values.

### "audience mismatch" or "token verification failed"

**Cause:** Token audience doesn't match resource server configuration.

**Solution:** Ensure AS and RS have consistent configuration:
```bash
# Check docker-compose.yml
RS_AUDIENCE=http://localhost:9090  # Should match in both AS and RS
```

### "required permission not present"

**Cause:** Agent capabilities don't match requested actions in authorization_details.

**Solution:** Ensure agent is registered with capabilities that match the requested actions (e.g., `orders:export` for the `/orders/export` endpoint).

### Browser redirect shows 404

**Cause:** Expected behavior - no app running on `localhost:5555`.

**Solution:** This is normal. Copy the `code` parameter from the URL in the address bar.

## Script Architecture

All scripts follow these patterns:

1. **Configuration** - Environment variables with sensible defaults
2. **Validation** - Check prerequisites before proceeding
3. **Execution** - Step-by-step flow with progress output
4. **Output** - JSON responses with `jq` formatting
5. **Guidance** - Next steps and usage instructions

Scripts use `set -euo pipefail` for strict error handling and fail fast on any error.

## Contributing

When adding new test scripts:

1. Follow the naming convention: `test_<flow_name>.sh`
2. Include a header comment explaining the script's purpose
3. Support configuration via environment variables
4. Provide clear output and error messages
5. Update this README with usage instructions
