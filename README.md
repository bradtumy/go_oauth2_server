# tokenator

An educational OAuth 2.0 authorisation server and companion resource server written in Go. The service supports:

- The authorisation code, refresh token, and client credentials grants.
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) Token Exchange for on-behalf-of (OBO) delegation.
- Rich authorisation requests (`authorization_details`) with permission hashing.
- Identity registration APIs for both humans and agents that drive every OAuth/OBO flow.

The project is intended for local development and demo scenarios. Tokens are JSON Web Tokens (JWTs) signed with RSA keys; the resource server verifies them using the same key material and a published JWKS endpoint.

## Contents

- [Architecture](#architecture)
- [Quickstart](#quickstart)
  - [Prerequisites](#prerequisites)
  - [Core Workflows](#core-workflows)
  - [Token Introspection](#token-introspection)
  - [Token Revocation](#token-revocation)
  - [Admin API Operations](#admin-api-operations)
  - [JWKS Endpoint](#jwks-endpoint)
  - [Health Checks](#health-checks)
  - [Common Patterns](#common-patterns)
  - [Debugging Tips](#debugging-tips)
- [Production Readiness](#production-readiness)
- [Prerequisites](#prerequisites)
- [Running locally](#running-locally)
- [Running with Docker Compose](#running-with-docker-compose)
- [Identity Registration & End-to-End OAuth/OBO with Registered Identities](#identity-registration--end-to-end-oauthobo-with-registered-identities)
  - [1. Run the services](#1-run-the-services)
  - [2. Register identities](#2-register-identities)
  - [3. Authorisation code flow](#3-authorisation-code-flow)
  - [4. Mint a subject assertion](#4-mint-a-subject-assertion)
  - [5. Perform RFC 8693 token exchange](#5-perform-rfc-8693-token-exchange)
  - [6. Call the resource server](#6-call-the-resource-server)
  - [7. Negative tests](#7-negative-tests)
  - [Postman collection](#postman-collection)
- [Tests](#tests)
- [Configuration](#configuration)
- [Project layout](#project-layout)

## Architecture

```
+----------------------+           +--------------------------+
|  Authorization Server |  OBO JWT  |      Resource Server     |
|  (cmd/as)             |---------> |      (cmd/rs)            |
|                      |           |                          |
| • /register/human    |           | • /accounts/{id}/orders/ |
| • /register/agent    |           |   export                 |
| • /oauth2/authorize  |           | • Validates JWT, perm,   |
| • /oauth2/token      |           |   authorization_details  |
| • /subject-assertion |           |                          |
| • /admin/clients     |           |                          |
+----------------------+           +--------------------------+
```

- **Authorization Server** – owns human and agent registrations, issues authorisation codes, access tokens, refresh tokens, subject assertions, and OBO tokens. All flows resolve identities from the in-memory identity store.
- **Resource Server** – a tiny API that expects an OBO access token. It verifies the signature, audience, issuer, human subject, actor information, `perm` claim, and `authorization_details` payload.

## Quickstart

This section covers the essential flows for using the Authorization Server (AS) and Resource Server (RS) after they're running. For detailed setup instructions, see [Running locally](#running-locally) or [Running with Docker Compose](#running-with-docker-compose).

### Prerequisites

Before using the services, ensure you have:
- Services running at `http://localhost:8080` (AS) and `http://localhost:9090` (RS)
- `curl` and `jq` installed for testing

**IMPORTANT:** You must seed OAuth clients before making any token requests:

```bash
make seed
```

This registers the demo clients (`agent-cli`, `human-web`) from the `clients/` directory into the SQLite database. Without this step, all token requests will fail with `invalid_client`. See [Seeding clients](#seeding-clients) for details.

### Core Workflows

#### 1. Client Credentials Grant (Machine-to-Machine)

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

#### 2. Authorization Code Grant (User Context)

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
```

**Response includes:**
- `access_token`: JWT with user identity (`sub`, `email`, `name`, `tenant_id`)
- `refresh_token`: Long-lived token for obtaining new access tokens
- `expires_in`: Access token lifetime

#### 3. Refresh Token Grant

Exchange a refresh token for a new access token without user interaction.

```bash
curl -sS -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=refresh_token' \
  -d "refresh_token=<REFRESH_TOKEN>" \
  -d 'client_id=human-web' | jq .
```

**Note:** Refresh token rotation is enabled. Each use generates a new refresh token and invalidates the old one. Reuse detection revokes the entire token family.

#### 4. RFC 8693 Token Exchange (On-Behalf-Of)

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

#### 5. Resource Server Access

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

## Prerequisites

- Go **1.24+**
- `curl`
- `sqlite3` (or set `AS_CLIENT_STORE=memory`)
- Optional: Docker & Docker Compose v2
- Optional: `make`

## Running locally

```bash
# Install dependencies
go mod tidy

# Start the authorisation server (AS)
ISSUER=http://localhost:8080 \
RS_AUDIENCE=http://localhost:9090 \
go run ./cmd/as

# In another terminal start the resource server (RS)
RS_AUDIENCE=http://localhost:9090 \
go run ./cmd/rs
```

Both services expose `/healthz` endpoints. Configuration is driven via environment variables (see [Configuration](#configuration)).

## Running with Docker Compose

```bash
docker compose up --build
```

The compose file publishes:

- Authorisation server: `http://localhost:8080`
- Resource server: `http://localhost:9090`

Set additional environment variables by editing `docker-compose.yml` or creating a local `.env` file.

## Identity Registration & End-to-End OAuth/OBO with Registered Identities

Every OAuth/OBO flow relies on registered identities. The built-in APIs store data in an in-memory, thread-safe data store. Optionally protect the registration endpoints by setting `AS_ADMIN_TOKEN` (or `ADMIN_TOKEN`) and sending `X-Admin-Token` headers.

### 1. Run the services

```bash
go run ./cmd/as
# or
docker compose up --build
```

### 2. Register identities

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
curl -sS http://localhost:8080/humans | jq .
curl -sS http://localhost:8080/agents | jq .
```

### Admin client registry

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

### Postman collection

Import the following collection and set the environment variables `BASE_URL`, `CLIENT_ID`, `CLIENT_SECRET`, `HUMAN_EMAIL`, `HUMAN_ID`, `AGENT_ID`, and `OBO_TOKEN`.

```json
{
  "info": {
    "name": "tokenator Demo",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "Register human",
      "request": {
        "method": "POST",
        "header": [{"key": "Content-Type", "value": "application/json"}],
        "url": "{{BASE_URL}}/register/human",
        "body": {
          "mode": "raw",
          "raw": "{\n  \"email\": \"{{HUMAN_EMAIL}}\",\n  \"name\": \"Alice Example\",\n  \"tenant_id\": \"default\"\n}"
        }
      }
    },
    {
      "name": "Register agent",
      "request": {
        "method": "POST",
        "header": [{"key": "Content-Type", "value": "application/json"}],
        "url": "{{BASE_URL}}/register/agent",
        "body": {
          "mode": "raw",
          "raw": "{\n  \"agent_id\": \"{{AGENT_ID}}\",\n  \"name\": \"Data Ingestor\",\n  \"client_id\": \"{{CLIENT_ID}}\",\n  \"capabilities\": [\"tickets.read\", \"tickets.write\"],\n  \"tenant_id\": \"default\"\n}"
        }
      }
    },
    {
      "name": "Token exchange",
      "request": {
        "method": "POST",
        "header": [{"key": "Content-Type", "value": "application/x-www-form-urlencoded"}],
        "url": "{{BASE_URL}}/oauth2/token",
        "body": {
          "mode": "urlencoded",
          "urlencoded": [
            {"key": "grant_type", "value": "urn:ietf:params:oauth:grant-type:token-exchange"},
            {"key": "subject_token", "value": "{{OBO_TOKEN}}"},
            {"key": "subject_token_type", "value": "urn:ietf:params:oauth:token-type:access_token"},
            {"key": "audience", "value": "http://localhost:9090"},
            {"key": "client_id", "value": "{{CLIENT_ID}}"},
            {"key": "client_secret", "value": "{{CLIENT_SECRET}}"},
            {"key": "authorization_details", "value": "[{\"type\":\"agent-action\",\"actions\":[\"tickets.export\"]}]"}
          ]
        }
      }
    }
  ]
}
```

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

## Project layout

```
cmd/
  as/   # Authorisation server
  rs/   # Demo resource server
internal/
  assertion/    # (legacy helper tooling)
  config/       # Environment-driven configuration
  identity/     # Identity types, validation, and HTTP handlers
  jwt/          # Minimal JWT signer/verification helpers
  obo/          # Token exchange helpers
  store/        # OAuth client/code/refresh stores and identity store implementations
scripts/        # Automation helpers
```
