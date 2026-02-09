# tokenator

[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An educational OAuth 2.0 authorization server and companion resource server written in Go, demonstrating modern OAuth flows including on-behalf-of (OBO) delegation.

## Features

- ✅ **Standard OAuth 2.0 Grants**: Authorization code with PKCE, client credentials, refresh token
- ✅ **RFC 8693 Token Exchange**: On-behalf-of (OBO) delegation for agent-on-human scenarios
- ✅ **Rich Authorization Requests**: Fine-grained permissions with `authorization_details`
- ✅ **Identity Management**: Built-in APIs for human and agent identity registration
- ✅ **Production Security**: PKCE enforcement, refresh token rotation, rate limiting
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

### 2. Authorization Code with PKCE (User Auth)

For web applications requiring user consent and identity.

**Step 1:** Register a human identity

```bash
curl -sS -X POST http://localhost:8080/register/human \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "alice@example.com",
    "name": "Alice Example",
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

**Step 3:** Initiate authorization (opens browser)

```bash
open "http://localhost:8080/oauth2/authorize?\
response_type=code&\
client_id=human-web&\
redirect_uri=http://localhost:5555/callback&\
scope=tickets.read&\
email=alice@example.com&\
code_challenge=${CODE_CHALLENGE}&\
code_challenge_method=S256"
```

The browser will redirect to `http://localhost:5555/callback?code=...` (which will show a 404 - this is expected since no app is running there). Copy the `code` parameter from the URL.

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

### 3. Refresh Token Grant

Exchange a refresh token for a new access token without user interaction.

```bash
curl -sS -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d "refresh_token=<REFRESH_TOKEN>" \
  -d 'client_id=human-web' | jq .
```

**Note:** Refresh token rotation is enabled. Each use generates a new refresh token and invalidates the old one. Reuse detection revokes the entire token family.

### 4. Token Exchange (On-Behalf-Of)

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

### 5. Resource Server Access

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
- Troubleshooting guide

**Quick test:**

```bash
# Run complete OBO flow (non-interactive)
./scripts/test_complete_obo_flow.sh

# Test authorization code flow (opens browser)
./scripts/test_auth_code_flow.sh

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
| `AS_RATE_LIMIT_AUTHORIZE_RPS`      | Rate limit (requests/sec) for `/oauth2/authorize`                                           | `5`                             |
| `AS_RATE_LIMIT_AUTHORIZE_BURST`    | Burst limit for `/oauth2/authorize`                                                         | `10`                            |
| `AS_RATE_LIMIT_TOKEN_RPS`          | Rate limit (requests/sec) for `/oauth2/token`                                               | `10`                            |
| `AS_RATE_LIMIT_TOKEN_BURST`        | Burst limit for `/oauth2/token`                                                             | `20`                            |
| `AS_RATE_LIMIT_INTROSPECT_RPS`     | Rate limit (requests/sec) for `/oauth2/introspect`                                          | `10`                            |
| `AS_RATE_LIMIT_INTROSPECT_BURST`   | Burst limit for `/oauth2/introspect`                                                        | `20`                            |
| `AS_RATE_LIMIT_ADMIN_RPS`          | Rate limit (requests/sec) for `/admin/*`                                                    | `5`                             |
| `AS_RATE_LIMIT_ADMIN_BURST`        | Burst limit for `/admin/*`                                                                  | `10`                            |

All configuration is logged at server startup (secrets are masked in logs).

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
