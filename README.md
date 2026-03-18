# tokenator

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An educational OAuth 2.0 authorization server and companion resource server written in Go, demonstrating modern OAuth flows including on-behalf-of (OBO) delegation.

## Features

- ✅ **User Authentication**: Login/logout with password-based authentication and session management
- ✅ **OAuth Consent Flow**: User consent pages showing requested permissions before authorization
- ✅ **Standard OAuth 2.0 Grants**: Authorization code with PKCE, client credentials, refresh token
- ✅ **RFC 7523 JWT Bearer Client Assertions**: Agent authentication with signed JWTs (no static secrets)
- ✅ **RFC 8693 Token Exchange**: On-behalf-of (OBO) delegation for agent-on-human scenarios
- ✅ **Rich Authorization Requests**: Fine-grained permissions with `authorization_details`
- ✅ **Identity Management**: Built-in APIs for human and agent identity registration
- ✅ **Production Security**: PKCE enforcement, refresh token rotation, rate limiting, bcrypt password hashing, JTI replay protection
- ✅ **JWT Tokens**: Self-contained JWTs with RSA signatures and JWKS endpoint
- ✅ **Admin API**: Dynamic client registration and management
- ✅ **Test Scripts**: Automated end-to-end test suite in `/scripts`

**Intended for:** Local development, demos, OAuth learning, and prototyping. See [Production Readiness](#production-readiness) for deployment considerations.

## Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Usage Guide](#usage-guide)
  - [Prerequisites](#prerequisites)
  - [Running Locally](#running-locally)
  - [Running with Docker](#running-with-docker)
  - [Seeding OAuth Clients](#seeding-oauth-clients)
- [OAuth Workflows](#oauth-workflows)
  - [1. Client Credentials (Machine-to-Machine)](#1-client-credentials-machine-to-machine)
  - [2. Authorization Code with PKCE (User Auth)](#2-authorization-code-with-pkce-user-auth)
  - [3. Refresh Token Grant](#3-refresh-token-grant)
  - [4. Token Exchange (On-Behalf-Of)](#4-token-exchange-on-behalf-of)
  - [5. Resource Server Access](#5-resource-server-access)
- [API Reference](#api-reference)
  - [Identity Registration](#identity-registration)
  - [Token Introspection](#token-introspection)
  - [Token Revocation](#token-revocation)
  - [Admin API](#admin-api)
  - [JWKS Endpoint](#jwks-endpoint)
  - [Health Checks](#health-checks)
- [Test Scripts](#test-scripts)
- [Troubleshooting](#troubleshooting)
- [Tests](#tests)
- [Configuration](#configuration)
- [Production Readiness](#production-readiness)
- [Project Structure](#project-structure)
- [Contributing](#contributing)
- [License](#license)

## Quick Start

Get tokenator running in 3 minutes:

```bash
# 1. Clone and navigate to the project
git clone https://github.com/bradtumy/tokenator.git
cd tokenator

# 2. Start services with Docker
docker compose up -d

# 3. Seed OAuth clients
make seed

# 4. Run end-to-end test
./scripts/test_complete_obo_flow.sh
```

**What just happened?**
- Authorization Server started on `:8080`
- Resource Server started on `:9090`
- Demo OAuth clients registered
- Complete OBO flow executed: identity registration → token exchange → resource access

📖 **Next:** Explore individual workflows in the [OAuth Workflows](#oauth-workflows) section or see [Test Scripts](#test-scripts) for automated testing.

## Architecture

tokenator implements a minimal OAuth 2.0 authorization server (AS) and resource server (RS) for educational purposes.

**Components:**
- **Authorization Server (AS)** – Issues tokens via multiple OAuth 2.0 grants, manages identities
- **Resource Server (RS)** – Validates tokens and serves protected resources

**Key Concepts:**
- **Scopes**: Coarse-grained permissions (e.g., `tickets.read`, `tickets.write`)
- **Authorization Details**: Fine-grained permissions defined in [RAR RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) (e.g., `orders:export`)
- **On-Behalf-Of (OBO)**: Token exchange allowing a service to act on behalf of a user ([RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693))

```
┌──────────┐         ┌───────────────┐         ┌──────────────┐
│  Client  │ OAuth   │     AS        │  Token  │      RS      │
│  (App)   ├────────►│ Port 8080     ├────────►│  Port 9090   │
└──────────┘         └───────────────┘         └──────────────┘
                            │
                            ▼
                     ┌─────────────┐
                     │  Identity   │
                     │  Service    │
                     └─────────────┘
```

## Usage Guide

### Prerequisites

Before using tokenator, ensure you have:
- Go 1.24+ (for local development)
- Docker and Docker Compose v2 (for containerized deployment)
- `curl` and `jq` for testing

⚠️ **IMPORTANT:** You must seed OAuth clients before making any token requests:

```bash
make seed
```

This registers demo clients (`agent-cli`, `human-web`) from the `clients/` directory into the SQLite database. Without this step, all token requests will fail with `invalid_client`. See [Seeding OAuth Clients](#seeding-oauth-clients) for details.

## OAuth Workflows

This section demonstrates the core OAuth 2.0 flows supported by tokenator. For automated testing, see [Test Scripts](#test-scripts).

### 1. Client Credentials (Machine-to-Machine)

Use this for service-to-service authentication without a user context.

```bash
curl -sS -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=agent-cli' \
  -d 'client_secret=agent-cli-secret' \
  -d 'scope=tickets.read' | jq .
```

**Response includes:**
- `access_token`: JWT containing client identity and scopes
- `expires_in`: Token lifetime (default 3600s)
- `token_type`: "Bearer"

### 2. JWT Bearer Client Assertions (RFC 7523) - Agent Authentication

Use RFC 7523 for **agent authentication without static client secrets**. Agents authenticate using signed JWT assertions with their private key.

**Security Benefits:**
- ✅ No static secrets stored or transmitted
- ✅ Cryptographic proof of identity
- ✅ Automatic replay protection via JTI validation
- ✅ Key rotation without client_id changes

**Step 1:** Generate RSA-2048 keypair

```bash
# Using the built-in tool
cd /tmp
~/dev/tokenator/tools/mint_rfc7523_assertion/mint_rfc7523_assertion -generate-keypair

# Or using openssl
openssl genrsa -out agent-private-key.pem 2048
openssl rsa -in agent-private-key.pem -pubout -out agent-public-key.pem
```

**Step 2:** Register agent with public key

```bash
PUBLIC_KEY=$(cat agent-public-key.pem)

curl -sS -X POST http://localhost:8080/admin/clients \
  -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_id\": \"agent-rfc7523\",
    \"client_type\": \"confidential\",
    \"public_key\": \"$PUBLIC_KEY\",
    \"key_algorithm\": \"RS256\",
    \"grant_types\": [\"client_credentials\"],
    \"scopes\": [\"tickets.read\", \"tickets.write\"]
  }" | jq .
```

**Step 3:** Generate JWT assertion (signed with private key)

```bash
ASSERTION=$(~/dev/tokenator/tools/mint_rfc7523_assertion/mint_rfc7523_assertion \
  -client-id agent-rfc7523 \
  -private-key agent-private-key.pem \
  -audience http://localhost:8080/token \
  -algorithm RS256)
```

**Step 4:** Request access token using JWT assertion

```bash
curl -sS -X POST http://localhost:8080/token \
  -d "grant_type=client_credentials" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$ASSERTION" \
  -d "scope=tickets.read" | jq .
```

**Response includes:**
- `access_token`: JWT containing agent identity and scopes
- `expires_in`: Token lifetime (default 3600s)
- `token_type`: "Bearer"

**Supported Algorithms:**
- RSA: RS256, RS384, RS512 (minimum 2048-bit keys)
- ECDSA: ES256, ES384, ES512 (minimum 256-bit keys)

**Testing:**
```bash
# Run comprehensive RFC 7523 test suite (includes attack scenarios)
~/dev/tokenator/scripts/test_rfc7523_client_assertion.sh

# Quick demonstration
~/dev/tokenator/scripts/quick_rfc7523_demo.sh
```

### 3. Authorization Code with PKCE (User Auth)

Requires **user authentication** via login page and consent before issuing tokens. This is the standard OAuth 2.0 flow for web and mobile applications.

**Step 1:** Register a human identity with a password

```bash
curl -sS -X POST http://localhost:8080/register/human \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "alice@example.com",
    "name": "Alice Example",
    "password": "SecurePassword123",
    "tenant_id": "default"
  }' | jq .
```

**Step 2:** Generate PKCE parameters (required for public clients)

> **Important:** Run Steps 2-4 in the same terminal session. The `CODE_VERIFIER` environment variable must persist from Step 2 through Step 4.

```bash
CODE_VERIFIER=$(openssl rand -base64 43 | tr -d '=+/' | head -c 43)
CODE_CHALLENGE=$(printf '%s' "${CODE_VERIFIER}" | openssl dgst -sha256 -binary | \
  openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Verify they're set (should output random strings)
echo "Verifier: ${CODE_VERIFIER}"
echo "Challenge: ${CODE_CHALLENGE}"
```

**Step 3:** Initiate authorization (opens browser to login page)

```bash
open "http://localhost:8080/oauth2/authorize?\
response_type=code&\
client_id=human-web&\
redirect_uri=http://localhost:5555/callback&\
scope=tickets.read&\
code_challenge=${CODE_CHALLENGE}&\
code_challenge_method=S256"
```

**What happens:**
1. Browser redirects to `/login` page (authentication required)
2. User enters email (`alice@example.com`) and password (`SecurePassword123`)
3. After successful login, consent page shows requested permissions
4. User clicks "Authorize" to approve the request
5. Browser redirects to `http://localhost:5555/callback?code=...` with authorization code

> **Note:** If no callback server is running on port 5555, you'll see a connection error. This is expected - simply copy the `code` parameter from the URL bar.

**Alternative:** Use the automated test script to see the complete flow:
```bash
./scripts/test_auth_flow.sh
```

**Step 4:** Exchange the authorization code for tokens

```bash
curl -sS -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d "code=<AUTHORIZATION_CODE>" \
  -d 'client_id=human-web' \
  -d "code_verifier=${CODE_VERIFIER}" \
  -d 'redirect_uri=http://localhost:5555/callback' | jq .
**Response includes:**
- `access_token`: JWT with user identity (`sub`, `email`, `name`, `tenant_id`)
- `refresh_token`: Long-lived token for obtaining new access tokens
- `expires_in`: Access token lifetime

### 4. Refresh Token Grant

Exchange a refresh token for a new access token without user interaction.

```bash
curl -sS -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d "refresh_token=<REFRESH_TOKEN>" \
  -d 'client_id=human-web' | jq .
```

**Note:** Refresh token rotation is enabled. Each use generates a new refresh token and invalidates the old one. Reuse detection revokes the entire token family.

### 5. Token Exchange (On-Behalf-Of)

Enable delegated access where an agent acts on behalf of a human with constrained permissions.

**Step 1:** Register an agent identity

```bash
curl -sS -X POST http://localhost:8080/register/agent \
  -H 'Content-Type: application/json' \
  -d '{
    "agent_id": "ingestor-42",
    "name": "Data Ingestor",
    "client_id": "agent-cli",
    "capabilities": ["tickets.read", "tickets.write"],
    "tenant_id": "default"
  }' | jq .
```

**Step 2:** Mint a subject assertion for the human

```bash
SUBJECT_ASSERTION=$(curl -sS -X POST http://localhost:8080/subject-assertion \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com"}' | jq -r .assertion)
```

**Step 3:** Perform token exchange with authorization details

```bash
curl -sS -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d "subject_token=${SUBJECT_ASSERTION}" \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  -d 'audience=http://localhost:9090' \
  -d 'client_id=agent-cli' \
  -d 'client_secret=agent-cli-secret' \
  --data-urlencode 'authorization_details=[{
    "type": "agent-action",
    "actions": ["tickets.export"],
    "constraints": {"resource_ids": ["acct:abc"]}
  }]' | jq .
```

**Response includes:**
- `access_token`: OBO JWT with `sub` (human), `act.actor` (agent), `perm` hash, and `authorization_details`
- `issued_token_type`: `urn:ietf:params:oauth:token-type:access_token`

The `perm` claim is a SHA-256 hash of the normalized `authorization_details`, enabling efficient permission verification.

### 6. Resource Server Access

Call protected endpoints with the OBO access token.

```bash
curl -sS -H "Authorization: Bearer <OBO_ACCESS_TOKEN>" \
  http://localhost:9090/accounts/acct:abc/orders/export | jq .
```

**The RS validates:**
- JWT signature and standard claims (exp, iss, aud)
- Human subject (`sub`)
- Agent actor (`act.actor` matches registered agent)
- Permission hash (`perm` matches authorization_details)
- Resource constraints (e.g., `resource_ids` contains requested account)

### Token Introspection

Check token validity and metadata.

```bash
curl -sS -X POST http://localhost:8080/oauth2/introspect \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "token=<ACCESS_OR_REFRESH_TOKEN>" \
  -d 'client_id=agent-cli' \
  -d 'client_secret=agent-cli-secret' | jq .
```

### Token Revocation

Revoke refresh tokens (access token revocation not supported for self-contained JWTs).

```bash
curl -sS -X POST http://localhost:8080/oauth2/revoke \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "token=<REFRESH_TOKEN>" \
  -d 'client_id=agent-cli' \
  -d 'client_secret=agent-cli-secret'
```

### Admin API Operations

Manage OAuth clients via the admin API (bound to `127.0.0.1:8082` by default). Set `AS_ADMIN_TOKEN` to require authentication.

```bash
# List all clients
curl -sS http://127.0.0.1:8082/admin/clients | jq .

# Create a new client
curl -sS -X POST http://127.0.0.1:8082/admin/clients \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-app",
    "client_secret": "supersecret",
    "name": "My Application",
    "client_type": "confidential",
    "grant_types": ["authorization_code", "refresh_token"],
    "redirect_uris": ["https://myapp.com/callback"],
    "scopes": ["profile", "email"]
  }' | jq .

# Get client details
curl -sS http://127.0.0.1:8082/admin/clients/my-app | jq .

# Update a client
curl -sS -X PUT http://127.0.0.1:8082/admin/clients/my-app \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-app",
    "client_secret": "newsecret",
    "name": "My Updated App",
    "client_type": "confidential",
    "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
    "redirect_uris": ["https://myapp.com/callback"],
    "scopes": ["profile", "email", "tickets.read"]
  }' | jq .

# Delete a client
curl -sS -X DELETE http://127.0.0.1:8082/admin/clients/my-app
```

### JWKS Endpoint

Retrieve public keys for JWT verification (used by RS and external services).

```bash
curl -sS http://localhost:8080/.well-known/jwks.json | jq .
```

### OAuth Authorization Server Metadata (RFC 8414)

Discover OAuth authorization server metadata.

```bash
curl -sS http://localhost:8080/.well-known/oauth-authorization-server | jq .
```

### OpenID Provider Metadata

Discover OpenID Connect metadata.

```bash
curl -sS http://localhost:8080/.well-known/openid-configuration | jq .
```

### OAuth Protected Resource Metadata (RFC 9728)

Discover protected resource metadata exposed by the RS.

```bash
curl -sS http://localhost:9090/.well-known/oauth-protected-resource | jq .
```

Run all well-known endpoint checks with explanations:

```bash
./scripts/test_well_known_endpoints.sh
```

Optional base URL overrides:

```bash
AS_BASE=http://localhost:8080 RS_BASE=http://localhost:9090 ./scripts/test_well_known_endpoints.sh
```

### Metadata Capability Matrix

| Endpoint | Purpose | Key fields currently exposed | Spec |
|---|---|---|---|
| `/.well-known/jwks.json` | Signing key discovery | `keys[]` with `kid`, `kty`, `alg`, `use`, `n`, `e` | JWKS (RFC 7517) |
| `/.well-known/oauth-authorization-server` | OAuth AS metadata | `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `introspection_endpoint`, `revocation_endpoint`, supported grants/auth methods | RFC 8414 |
| `/.well-known/openid-configuration` | OIDC provider metadata | `issuer`, OAuth endpoints, `jwks_uri`, response/grant support, signing alg support | OIDC Discovery |
| `/.well-known/oauth-protected-resource` | Resource metadata for clients/AS | `resource`, `authorization_servers`, `jwks_uri`, `bearer_methods_supported` | RFC 9728 |

Notes:
- Metadata intentionally advertises only capabilities currently implemented by tokenator.
- OIDC metadata is provided for ecosystem compatibility; full OIDC feature parity is not implied.

### Health Checks

Verify service availability.

```bash
# Authorization Server
curl -sS http://localhost:8080/healthz

# Resource Server
curl -sS http://localhost:9090/healthz
```

### Common Patterns

**Pattern 1: Machine acting on behalf of user**
1. User obtains access token via authorization code grant
2. User's access token used as `subject_token` in token exchange
3. Machine client receives OBO token with constrained permissions
4. Machine uses OBO token to access RS on user's behalf

**Pattern 2: Scheduled job acting on behalf of user**
1. Mint subject assertion for user (requires user email/ID)
2. Exchange assertion for OBO token with specific `authorization_details`
3. Job uses OBO token to perform authorized actions
4. Token expires after short TTL (default 15min)

**Pattern 3: Long-lived background service**
1. Use refresh token grant to maintain user session
2. Monitor token expiration and refresh proactively
3. Handle refresh token rotation (store new tokens)
4. Implement reuse detection handling (re-authenticate if family revoked)

### Debugging Tips

- **Decode JWTs:** Use [jwt.io](https://jwt.io) or `jq -R 'split(".") | .[1] | @base64d | fromjson'`
- **Check logs:** Both AS and RS log detailed request/validation information
- **Verify identity registration:** `curl http://localhost:8080/humans` and `curl http://localhost:8080/agents`
- **Validate client config:** `curl http://127.0.0.1:8082/admin/clients/<client_id>`
- **Test token validity:** Use `/oauth2/introspect` endpoint
- **Common errors:**
  - `400 invalid_request`: Missing required parameters or unknown identity
  - `401 unauthorized`: Invalid client credentials
  - `403 forbidden`: Agent lacks required capabilities for requested actions
  - `429 too_many_requests`: Rate limit exceeded

## Authentication

tokenator implements secure user authentication with login/logout, password management, and session-based security for the OAuth authorization code grant flow.

### User Registration with Passwords

Register users with secure password hashing (bcrypt, cost factor 12):

```bash
curl -X POST http://localhost:8080/register/human \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "user@example.com",
    "name": "User Name",
    "password": "SecurePassword123",
    "tenant_id": "default"
  }'
```

> **Note:** The `password` field is optional. Users without passwords can only login in `DEV_MODE=true`.

### Login Flow

When users access `/oauth2/authorize`, they are redirected to `/login` if not authenticated:

1. **Login Page** - Users enter email and password
2. **Authentication** - Credentials verified against bcrypt hash
3. **Session Creation** - HTTP-only session cookie issued (8 hour max, 30 min idle timeout)
4. **Consent Page** - User sees requested scopes and approves/denies
5. **Authorization Code** - Issued only after consent approval

### Session Management

- **Session Storage**: In-memory (production should use Redis/database)
- **Session Cookie**: HTTP-only, SameSite=Lax, 8-hour absolute timeout, 30-minute idle timeout
- **CSRF Protection**: CSRF tokens generated per session
- **Automatic Cleanup**: Background worker removes expired sessions every 15 minutes

### Development Mode

Enable `DEV_MODE=true` to allow passwordless login for testing:

```bash
DEV_MODE=true go run ./cmd/as
```

In dev mode, users can login with just their email if no password is set. The login page displays a visual indicator when dev mode is active.

### Logout

End a user session:

```bash
# Programmatically
curl -X POST http://localhost:8080/logout \
  -H 'Cookie: session_id=<SESSION_ID>'

# Or visit in browser
open http://localhost:8080/logout
```

Logout clears the session cookie and removes the session from the store.

### Security Considerations

- ✅ Passwords hashed with bcrypt (cost factor 12, industry standard)
- ✅ Minimum password length: 8 characters
- ✅ HTTP-only cookies prevent XSS attacks
- ✅ SameSite=Lax prevents CSRF attacks
- ✅ Session expiration enforced (idle and absolute timeouts)
- ⚠️ In-memory session storage (use Redis/database for production)
- ⚠️ No rate limiting on login endpoint (add for production)
- ⚠️ No account lockout after failed attempts (add for production)
- ⚠️ No password reset flow (add for production)

## Production Readiness

This project started as a lab. The following hardening has been added to help move toward production readiness without a major refactor:

- **Authorization code hardening:** exact redirect URI matching, PKCE (S256) required for public clients, and one-time authorization code use with TTLs.
- **Refresh token safety:** refresh token rotation with reuse detection (reuse revokes the entire family).
- **Key management:** RSA keys with `kid` and JWKS publication; optional multi-key JWKS for overlap during rotation.
- **Rate limiting:** configurable token bucket limits for `/oauth2/authorize`, `/oauth2/token`, `/oauth2/introspect`, and `/admin/*`.
- **Introspection and revocation:** `/oauth2/introspect` and `/oauth2/revoke` supported for refresh tokens (access token revocation is not supported in-memory).

**Still not production complete:**

- No OIDC discovery or ID token support.
- Access token revocation is not persisted or enforced (JWTs are self-contained).
- HA/statelessness requires moving codes/refresh tokens to shared storage.
- Metrics and structured audit logs are minimal; see `docs/PROD_READINESS_PLAN.md`.

## Running Locally

```bash
# Install dependencies
go mod tidy

# Start the Authorization Server (AS)
ISSUER=http://localhost:8080 \
RS_AUDIENCE=http://localhost:9090 \
go run ./cmd/as

# In another terminal, start the Resource Server (RS)
RS_AUDIENCE=http://localhost:9090 \
go run ./cmd/rs
```

Both services expose `/healthz` endpoints. Configuration is driven via environment variables (see [Configuration](#configuration)).

## Running with Docker

```bash
docker compose up --build
```

The compose file publishes:
- Authorization Server: `http://localhost:8080`
- Resource Server: `http://localhost:9090`

To stop services:

```bash
docker compose down
```

Set additional environment variables by editing [docker-compose.yml](docker-compose.yml) or creating a `.env` file.

## Seeding OAuth Clients

Client registrations are stored in SQLite (`data/clients.db`) by default. Before making any OAuth requests, seed the demo clients:

```bash
make seed
```

Or manually:

```bash
AS_CLIENTS_DB=./data/clients.db ./scripts/seed_clients.sh
```

The seed script reads client configurations from `clients/*.json` and registers them. The demo client (`agent-cli`) has these credentials:
- **Client ID:** `agent-cli`
- **Client Secret:** `agent-cli-secret`
- **Scopes:** `tickets.read`, `tickets.write`, `refunds.create`

⚠️ **Without seeding clients first, all OAuth requests will fail with `invalid_client` errors.**

## API Reference

This section covers additional endpoints beyond the core OAuth workflows documented above.

### Identity Registration

Register human users and agent identities for use in OBO flows.

```bash
# Create a human
curl -sS -X POST http://localhost:8080/register/human \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","name":"Alice Example","tenant_id":"default"}' | jq .

# Create an agent (client_id must match your OAuth client)
curl -sS -X POST http://localhost:8080/register/agent \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"ingestor-42","name":"Data Ingestor","client_id":"agent-cli","capabilities":["tickets.read","tickets.write"],"tenant_id":"default"}' | jq .
```

Optional administrative helpers:

```bash
# List humans
curl -sS http://localhost:8080/humans | jq .

# List agents
curl -sS http://localhost:8080/agents | jq .
```

**Security:** Protect these endpoints by setting `AS_ADMIN_TOKEN` and including `X-Admin-Token: <token>` header.

### Seeding Identities

Bootstrap demo identities by creating a JSON file and pointing `SEED_IDENTITIES_JSON` at it before starting the server:

```json
{
  "humans": [
    {
      "email": "alice@example.com",
      "name": "Alice Example",
      "tenant_id": "default"
    }
  ],
  "agents": [
    {
      "agent_id": "ingestor-42",
      "name": "Data Ingestor",
      "client_id": "agent-cli",
      "capabilities": ["tickets.read", "tickets.write"],
      "tenant_id": "default"
    }
  ]
}
```

```bash
SEED_IDENTITIES_JSON=./data/seed.json go run ./cmd/as
```

When using Docker Compose, mount the file and set the environment variable in `docker-compose.yml`.

### Token Introspection

Client registrations are managed via the admin API bound to `127.0.0.1` (default `127.0.0.1:8082`). Set `AS_ADMIN_TOKEN` and include `Authorization: Bearer <token>` when calling:

- `POST   /admin/clients`
- `GET    /admin/clients`
- `GET    /admin/clients/{client_id}`
- `PUT    /admin/clients/{client_id}`
- `DELETE /admin/clients/{client_id}`

Set `AS_ADMIN_TOKEN` before starting the AS so the admin API and registration endpoints require auth:

```bash
export AS_ADMIN_TOKEN=dev-admin-token
go run ./cmd/as
```

Example client registry calls:

```bash
# List clients
curl -sS http://127.0.0.1:8082/admin/clients \
  -H "Authorization: Bearer ${AS_ADMIN_TOKEN}" | jq .

# Create a client
curl -sS -X POST http://127.0.0.1:8082/admin/clients \
  -H "Authorization: Bearer ${AS_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "agent-cli",
    "client_secret": "agent-cli-secret",
    "name": "Agent CLI",
    "grant_types": ["client_credentials", "authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"],
    "redirect_uris": ["http://localhost:5555/callback"]
  }' | jq .
```

### 3. Authorisation code flow

High-level steps:

1. Redirect the user to `/oauth2/authorize` with `response_type=code`.
2. Capture the `code` from the redirect URI.
3. Exchange the code at `/oauth2/token` for access/refresh tokens.

```bash
# Generate a PKCE verifier/challenge for public clients
CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/')
CODE_CHALLENGE=$(printf '%s' "${CODE_VERIFIER}" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')

# Launch the authorisation request (use either human_id or email)
open "http://localhost:8080/oauth2/authorize?response_type=code&client_id=human-web&redirect_uri=http://localhost:5555/callback&scope=tickets.read&email=alice@example.com&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

# Exchange the code for tokens
curl -sS -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'code=<CODE_FROM_REDIRECT>' \
  -d 'client_id=human-web' \
  -d "code_verifier=${CODE_VERIFIER}" \
  -d 'redirect_uri=http://localhost:5555/callback' | jq .
```

The access token’s `sub` claim equals the registered human ID, and includes `email`, `name`, and `tenant_id` claims.

### 4. Mint a subject assertion

```bash
curl -sS -X POST http://localhost:8080/subject-assertion \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com"}' | jq .
```

Subject assertions are short-lived JWTs (`iss = aud =` authorisation server) used as `subject_token` in token exchange requests.

### 5. Perform RFC 8693 token exchange

```bash
curl -sS -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d "subject_token=<SUBJECT_ASSERTION_OR_ACCESS_TOKEN>" \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  -d 'audience=http://localhost:9090' \
  -d 'client_id=agent-cli' \
  -d 'client_secret=agent-cli-secret' \
  --data-urlencode 'authorization_details=[{"type":"agent-action","actions":["tickets.export"],"constraints":{"resource_ids":["acct:abc"]}}]' | jq .
```

- The server supports token exchange (RFC 8693), so you can use the above request to trade a subject token for an on-behalf-of access token.
- The `subject_token` must resolve to a registered human.
- The authenticated client (optionally overridden via `agent_id`) must resolve to a registered agent with matching capabilities.
- The returned OBO token contains `sub` (human ID) and an `act` claim whose `actor` value equals the registered agent ID.

### 6. Call the resource server

```bash
curl -sS -H "Authorization: Bearer <OBO_ACCESS_TOKEN>" \
  http://localhost:9090/accounts/acct:abc/orders/export | jq .
```

### 7. Negative tests

- Request `/oauth2/authorize` without `human_id`/`email` → `400 invalid_request`.
- Perform token exchange with an unknown agent or mismatched `client_id` → `400 invalid_request`.
- Request OBO permissions that the agent is not entitled to → `403 invalid_request` with `no permissions` message.

### Seeding identities

Bootstrap demo data by creating a JSON file and pointing `SEED_IDENTITIES_JSON` at it before starting the server:

```jsonc
{
  "humans": [
    {
      "email": "alice@example.com",
      "name": "Alice Example",
      "tenant_id": "default"
    }
  ],
  "agents": [
    {
      "agent_id": "ingestor-42",
      "name": "Data Ingestor",
      "client_id": "agent-cli",
      "capabilities": ["tickets.read", "tickets.write"],
      "tenant_id": "default"
    }
  ]
}
```

```bash
SEED_IDENTITIES_JSON=./data/seed.json go run ./cmd/as
```

When using Docker Compose, mount the file and set the environment variable in `docker-compose.yml`.

### Seeding clients

Client registrations live in SQLite by default. Seed the demo clients with:

```bash
make seed
# or
AS_CLIENTS_DB=./data/clients.db ./scripts/seed_clients.sh
```

The seed files live in `clients/*.json`. Update those files (or add new ones) to register additional clients.

Example client credentials grant:

```bash
curl -sS -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'client_id=agent-cli' \
  -d 'client_secret=agent-cli-secret' \
  -d 'scope=tickets.read' | jq .
```

## Test Scripts

tokenator includes comprehensive test scripts to validate all OAuth flows. These scripts automate the manual steps shown above and are ideal for CI/CD pipelines or local development.

📖 **See [scripts/README.md](scripts/README.md) for complete documentation**, including:

- End-to-end OBO flow automation
- Individual grant type tests  
- PKCE parameter generation
- Token exchange workflows
- **Authentication flow testing**
- Troubleshooting guide

**Quick tests:**

```bash
# Test complete authentication flow (login → consent → token exchange)
./scripts/test_auth_flow.sh

# Run complete OBO flow (non-interactive)
./scripts/test_complete_obo_flow.sh

# Test authorization code flow (opens browser)
./scripts/test_auth_code_flow.sh
```

# Test client credentials grant
./scripts/test_client_credentials.sh
```

All scripts require Docker services running and clients seeded (`make seed`).

## Troubleshooting

### Common Errors

**`invalid_client` or `unknown client` error:**
- Ensure clients are seeded: `make seed`
- Verify client exists: `curl http://127.0.0.1:8082/admin/clients`
- Check client_id spelling and credentials

**`invalid_scope` or `scope not allowed` error:**
- Requested scopes must match those configured for the client
- Demo client scopes: `tickets.read`, `tickets.write`, `refunds.create`
- Check client config: `curl http://127.0.0.1:8082/admin/clients/<client_id>`

**PKCE validation fails:**
- Code verifier must be 43-128 characters (RFC 7636)
- Generate correctly: `openssl rand -base64 43 | tr -d '=+/' | head -c 43`
- Ensure CODE_VERIFIER persists from authorization to token exchange

**Token verification fails (`unknown kid` or signature error):**
- AS and RS must use matching key ID (default: `dev-rs256`)
- Check docker-compose.yml: `AS_SIGNING_KEY_ID=dev-rs256`
- RS fetches JWKS from AS: verify AS is running on port 8080

**`audience mismatch` error:**
- Ensure RS_AUDIENCE matches between AS and RS
- Default: `http://localhost:9090`
- When using Docker, use `localhost` not internal hostnames

**`permission denied` or `required permission not present`:**
- Agent capabilities must match requested `authorization_details` actions
- Example: Agent needs `orders:export` capability to request `actions:["orders:export"]`
- Check agent registration: `curl http://localhost:8080/agents`

**Authorization code redirect shows 404:**
- This is expected behavior - no app is running on the redirect URI
- Copy the `code` parameter from the URL bar manually

**OBO token exchange fails (`invalid_request` or `unknown identity`):**
- Ensure human identity is registered: `curl http://localhost:8080/humans`
- Ensure agent identity is registered: `curl http://localhost:8080/agents`
- Subject assertion email must match registered human
- Agent's `client_id` must match OAuth client

### Debugging Tips

- **Decode JWTs:** Use [jwt.io](https://jwt.io) or `echo $TOKEN | jq -R 'split(".") | .[1] | @base64d | fromjson'`
- **Check service logs:** Both AS and RS log detailed request/validation information
- **Verify identity registration:** `curl http://localhost:8080/humans` and `curl http://localhost:8080/agents`
- **Validate client config:** `curl http://127.0.0.1:8082/admin/clients/<client_id>`
- **Test token validity:** Use `/oauth2/introspect` endpoint
- **Enable verbose output:** Test scripts support DEBUG=1 environment variable

## Tests

```bash
go test ./...
```

Unit tests cover validation logic, the in-memory identity store, HTTP handlers, and end-to-end OAuth/OBO flows via `httptest`.

## Configuration

| Environment variable               | Description                                                                                  | Default                         |
| ---------------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------- |
| `ISSUER`                           | Issuer used in all minted tokens                                                             | `http://localhost:8080`         |
| `RS_AUDIENCE`                      | Audience for access and OBO tokens                                                           | `http://localhost:9090`         |
| `DEV_MODE`                         | Enable development mode (allows passwordless login for users without passwords)              | `false`                         |
| `AS_ADMIN_TOKEN`                   | Shared secret that gates `/register/*` (`X-Admin-Token`) and `/admin/*` (`Authorization: Bearer`) endpoints | unset          |
| `ADMIN_TOKEN`                      | Legacy alias for `AS_ADMIN_TOKEN`                                                            | unset                           |
| `ALLOW_LEGACY_HARDCODED`           | Set to `true` to allow legacy hard-coded users/agents (development only)                    | `false`                         |
| `SEED_IDENTITIES_JSON`             | Path to a JSON file containing initial humans/agents (`{"humans":[],"agents":[]}`)           | unset                           |
| `AS_CLIENTS_DB`                    | SQLite database path for client registrations                                               | `data/clients.db`               |
| `AS_CLIENT_STORE`                  | Client store driver (`sqlite` or `memory`)                                                  | `sqlite`                        |
| `AS_ADMIN_ADDR`                    | Bind address for the admin client registry API                                              | `127.0.0.1:8082`                |
| `AS_SIGNING_KEY_PEM`               | RSA private key PEM (single key fallback)                                                   | embedded dev key                |
| `AS_SIGNING_KEY_PATH`              | Path to RSA private key PEM                                                                  | unset                           |
| `AS_SIGNING_KEYS_DIR`              | Directory of RSA private keys (filename base = `kid`)                                        | unset                           |
| `AS_SIGNING_KEY_ID`                | Active JWT header `kid` (when using `AS_SIGNING_KEYS_DIR`)                                   | `dev-rs256`                     |
| `AS_SIGNING_KEY_ROTATION_SECONDS`  | Interval to reload keys from `AS_SIGNING_KEYS_DIR` (0 disables)                              | `0`                             |
| `AS_CODE_TTL_SECONDS`              | Authorisation code lifetime (seconds)                                                       | `120`                           |
| `AS_ACCESS_TOKEN_TTL_SECONDS`      | Access token lifetime (seconds)                                                             | `3600`                          |
| `AS_REFRESH_TOKEN_TTL_SECONDS`     | Refresh token lifetime (seconds)                                                            | `86400`                         |
| `AS_OBO_TOKEN_TTL_SECONDS`         | OBO token lifetime (seconds)                                                                | `900`                           |
| `ENABLE_RAR`                       | Enable Rich Authorization Requests (RFC 9396). Set to `false` for scope-only authorization | `true`                          |
| `AS_RATE_LIMIT_AUTHORIZE_RPS`      | Rate limit (requests/sec) for `/oauth2/authorize`                                           | `5`                             |
| `AS_RATE_LIMIT_AUTHORIZE_BURST`    | Burst limit for `/oauth2/authorize`                                                         | `10`                            |
| `AS_RATE_LIMIT_TOKEN_RPS`          | Rate limit (requests/sec) for `/oauth2/token`                                               | `10`                            |
| `AS_RATE_LIMIT_TOKEN_BURST`        | Burst limit for `/oauth2/token`                                                             | `20`                            |
| `AS_RATE_LIMIT_INTROSPECT_RPS`     | Rate limit (requests/sec) for `/oauth2/introspect`                                          | `10`                            |
| `AS_RATE_LIMIT_INTROSPECT_BURST`   | Burst limit for `/oauth2/introspect`                                                        | `20`                            |
| `AS_RATE_LIMIT_ADMIN_RPS`          | Rate limit (requests/sec) for `/admin/*`                                                    | `5`                             |
| `AS_RATE_LIMIT_ADMIN_BURST`        | Burst limit for `/admin/*`                                                                  | `10`                            |

All configuration is logged at server startup (secrets are masked in logs).

### Rich Authorization Requests (RAR)

Tokenator supports [RFC 9396 Rich Authorization Requests](https://www.rfc-editor.org/rfc/rfc9396.html) for fine-grained permissions using `authorization_details`.

**To disable RAR and use scope-only authorization:**

```bash
# In .env or docker-compose.yml
ENABLE_RAR=false
```

**When RAR is disabled:**
- Token exchange requests with `authorization_details` are rejected (400 Bad Request)
- Only `scope` parameter is accepted
- Tokens contain only `scope` claim (no `authorization_details`)
- Resource server ignores `authorization_details` if present in tokens
- Forces use of consent-based authorization flow

**Use case:** Educational comparison of coarse-grained (scope) vs fine-grained (RAR) authorization, and enforcing proper human consent validation.

**Test both modes:**

```bash
# Test with RAR enabled (default)
./scripts/test_complete_obo_flow.sh

# Test with RAR disabled
ENABLE_RAR=false USE_SCOPE_ONLY=true ./scripts/test_complete_obo_flow.sh

# Or use dedicated script
./scripts/test_scope_only_flow.sh
```

## Project Structure

```
cmd/
  as/           # Authorization Server
  rs/           # Resource Server
  seed-clients/ # Client seeding utility
internal/
  admin/        # Client management
  assertion/    # Subject assertion minting
  config/       # Environment-driven configuration
  http/         # HTTP utilities
  identity/     # Identity types, validation, and handlers
  jwt/          # JWT signing and verification
  obo/          # Token exchange (OBO) logic
  random/       # Secure random ID generation
  ratelimit/    # Rate limiting
  server/       # Server interfaces
  store/        # Storage implementations (SQLite, memory)
    mem/        # In-memory stores
    sqlite/     # SQLite stores
scripts/        # Test automation scripts
clients/        # Demo OAuth client configurations
data/           # Runtime data (databases, logs)
docs/           # Production readiness documentation
```

## Contributing

Contributions are welcome! This project is designed for educational purposes, focusing on OAuth 2.0 and token exchange patterns.

**How to contribute:**

1. **Fork the repository** and create a feature branch
2. **Make your changes** with clear commit messages
3. **Add tests** for new functionality
4. **Run the test suite:** `go test ./...`
5. **Test manually** using the test scripts in `scripts/`
6. **Submit a pull request** with a description of your changes

**Areas for improvement:**

- Additional OAuth grant types (device flow, SAML bearer)
- OIDC support (ID tokens, UserInfo endpoint, discovery)
- Production-ready storage backends (PostgreSQL, Redis)
- Observability improvements (structured logging, metrics, tracing)
- Additional test coverage
- Documentation improvements

**Guidelines:**

- Follow Go conventions and idioms
- Keep dependencies minimal
- Maintain backward compatibility where possible
- Document configuration changes in README
- Update test scripts when adding new endpoints

## License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

**Summary:** You are free to use, modify, and distribute this software for any purpose, including commercial applications, as long as the original license and copyright notice are included.

---

**tokenator** - An educational OAuth 2.0 server demonstrating authorization code flow, PKCE, refresh tokens, and RFC 8693 token exchange (OBO).
