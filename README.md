# go_oauth2_server

An educational OAuth 2.0 authorisation server and companion resource server written in Go. The service supports:

- The authorisation code, refresh token, and client credentials grants.
- [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) Token Exchange for on-behalf-of (OBO) delegation.
- Rich authorisation requests (`authorization_details`) with permission hashing.
- Identity registration APIs for both humans and agents that drive every OAuth/OBO flow.

The project is intended for local development and demo scenarios. Tokens are JSON Web Tokens (JWTs) signed with a symmetric key; the resource server verifies them using the shared key and a published JWKS endpoint.

## Contents

- [Architecture](#architecture)
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
| • /authorize         |           | • Validates JWT, perm,   |
| • /token             |           |   authorization_details  |
| • /subject-assertion |           |                          |
+----------------------+           +--------------------------+
```

- **Authorization Server** – owns human and agent registrations, issues authorisation codes, access tokens, refresh tokens, subject assertions, and OBO tokens. All flows resolve identities from the in-memory identity store.
- **Resource Server** – a tiny API that expects an OBO access token. It verifies the signature, audience, issuer, human subject, actor information, `perm` claim, and `authorization_details` payload.

## Prerequisites

- Go **1.22+**
- `curl`
- Optional: Docker & Docker Compose v2
- Optional: `make`

## Running locally

```bash
# Install dependencies
go mod tidy

# Start the authorisation server
ISSUER=http://localhost:8080 \
RS_AUDIENCE=http://localhost:9090 \
go run ./cmd/as

# In another terminal start the resource server
RS_AUDIENCE=http://localhost:9090 \
AS_JWKS_URL=http://localhost:8080/.well-known/jwks.json \
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

Every OAuth/OBO flow relies on registered identities. The built-in APIs store data in an in-memory, thread-safe data store. Optionally protect the registration endpoints by setting `ADMIN_TOKEN` and sending `X-Admin-Token` headers.

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
  -d '{"agent_id":"ingestor-42","name":"Data Ingestor","client_id":"client-xyz","capabilities":["orders:read","orders:export"],"tenant_id":"default"}' | jq .
```

Optional administrative helpers:

```bash
curl -sS http://localhost:8080/humans | jq .
curl -sS http://localhost:8080/agents | jq .
```

### 3. Authorisation code flow

```bash
# Launch the authorisation request (use either human_id or email)
open "http://localhost:8080/authorize?response_type=code&client_id=client-xyz&redirect_uri=http://localhost:8081/cb&scope=openid&email=alice@example.com"

# Exchange the code for tokens
curl -sS -X POST http://localhost:8080/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d 'code=<CODE_FROM_REDIRECT>' \
  -d 'client_id=client-xyz' \
  -d 'client_secret=secret-xyz' \
  -d 'redirect_uri=http://localhost:8081/cb' | jq .
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
curl -sS -X POST http://localhost:8080/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  -d "subject_token=<SUBJECT_ASSERTION_OR_ACCESS_TOKEN>" \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  -d 'audience=http://localhost:9090' \
  -d 'client_id=client-xyz' \
  -d 'client_secret=secret-xyz' \
  --data-urlencode 'authorization_details=[{"type":"agent-action","actions":["orders:export"],"constraints":{"resource_ids":["acct:abc"]}}]' | jq .
```

- The `subject_token` must resolve to a registered human.
- The authenticated client (optionally overridden via `agent_id`) must resolve to a registered agent with matching capabilities.
- The returned OBO token contains `sub` (human ID) and an `act` claim whose `actor` value equals the registered agent ID.

### 6. Call the resource server

```bash
curl -sS -H "Authorization: Bearer <OBO_ACCESS_TOKEN>" \
  http://localhost:9090/accounts/acct:abc/orders/export | jq .
```

### 7. Negative tests

- Request `/authorize` without `human_id`/`email` → `400 invalid_request`.
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
      "client_id": "client-xyz",
      "capabilities": ["orders:read", "orders:export"],
      "tenant_id": "default"
    }
  ]
}
```

```bash
SEED_IDENTITIES_JSON=./data/seed.json go run ./cmd/as
```

When using Docker Compose, mount the file and set the environment variable in `docker-compose.yml`.

### Postman collection

Import the following collection and set the environment variables `BASE_URL`, `CLIENT_ID`, `CLIENT_SECRET`, `HUMAN_EMAIL`, `HUMAN_ID`, `AGENT_ID`, and `OBO_TOKEN`.

```json
{
  "info": {
    "name": "go_oauth2_server Demo",
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
          "raw": "{\n  \"agent_id\": \"{{AGENT_ID}}\",\n  \"name\": \"Data Ingestor\",\n  \"client_id\": \"{{CLIENT_ID}}\",\n  \"capabilities\": [\"orders:read\", \"orders:export\"],\n  \"tenant_id\": \"default\"\n}"
        }
      }
    },
    {
      "name": "Token exchange",
      "request": {
        "method": "POST",
        "header": [{"key": "Content-Type", "value": "application/x-www-form-urlencoded"}],
        "url": "{{BASE_URL}}/token",
        "body": {
          "mode": "urlencoded",
          "urlencoded": [
            {"key": "grant_type", "value": "urn:ietf:params:oauth:grant-type:token-exchange"},
            {"key": "subject_token", "value": "{{OBO_TOKEN}}"},
            {"key": "subject_token_type", "value": "urn:ietf:params:oauth:token-type:access_token"},
            {"key": "audience", "value": "http://localhost:9090"},
            {"key": "client_id", "value": "{{CLIENT_ID}}"},
            {"key": "client_secret", "value": "{{CLIENT_SECRET}}"},
            {"key": "authorization_details", "value": "[{\"type\":\"agent-action\",\"actions\":[\"orders:export\"]}]"}
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

| Environment variable          | Description                                                                                  | Default                         |
| ----------------------------- | -------------------------------------------------------------------------------------------- | ------------------------------- |
| `ISSUER`                      | Issuer used in all minted tokens                                                             | `http://localhost:8080`         |
| `RS_AUDIENCE`                 | Audience for access and OBO tokens                                                           | `http://localhost:9090`         |
| `ADMIN_TOKEN`                 | Optional shared secret that gates `/register/*` endpoints (`X-Admin-Token` header required) | unset                           |
| `ALLOW_LEGACY_HARDCODED`      | Set to `true` to allow legacy hard-coded users/agents (development only)                    | `false`                         |
| `SEED_IDENTITIES_JSON`        | Path to a JSON file containing initial humans/agents (`{"humans":[],"agents":[]}`)       | unset                           |
| `AS_DEFAULT_CLIENT_ID`        | Default OAuth client ID                                                                      | `client-xyz`                    |
| `AS_DEFAULT_CLIENT_SECRET`    | Default OAuth client secret                                                                  | `secret-xyz`                    |
| `AS_SIGNING_KEY_BASE64`       | Base64-encoded HMAC signing key                                                              | `ZGV2LXNpZ25pbmcta2V5LTEyMzQ=`  |
| `AS_SIGNING_KEY_ID`           | JWT header `kid`                                                                             | `dev-hs256`                     |
| `AS_CODE_TTL_SECONDS`         | Authorisation code lifetime (seconds)                                                        | `120`                           |
| `AS_ACCESS_TOKEN_TTL_SECONDS` | Access token lifetime (seconds)                                                              | `3600`                          |
| `AS_REFRESH_TOKEN_TTL_SECONDS`| Refresh token lifetime (seconds)                                                             | `86400`                         |
| `AS_OBO_TOKEN_TTL_SECONDS`    | OBO token lifetime (seconds)                                                                 | `900`                           |

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

