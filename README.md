# go_oauth2_server

An educational OAuth 2.0 authorization server and demo resource server written in Go. The service now supports standard OAuth 2.0 grants **and** [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) Token Exchange for on-behalf-of (OBO) delegation scenarios. Tokens are minted as JSON Web Tokens (JWTs) signed with a shared symmetric key, and a small resource server validates the resulting OBO tokens.

## Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Running locally](#running-locally)
- [Running with Docker](#running-with-docker)
- [RFC 8693 Token Exchange (On-Behalf-Of) – How to Test](#rfc-8693-token-exchange-on-behalf-of--how-to-test)
  - [Step 1 – Obtain a user access token](#step-1--obtain-a-user-access-token)
  - [Step 2 – Mint an actor client assertion](#step-2--mint-an-actor-client-assertion)
  - [Step 3 – Exchange for an OBO token](#step-3--exchange-for-an-obo-token)
  - [Step 4 – Call the resource server](#step-4--call-the-resource-server)
  - [Negative testing ideas](#negative-testing-ideas)
  - [Postman collection](#postman-collection)
- [Automation & scripts](#automation--scripts)
- [Configuration](#configuration)
- [Project layout](#project-layout)

## Architecture

```
+----------------------+           +--------------------------+
|  Authorization Server |  OBO JWT  |      Resource Server     |
|  (cmd/as)             |---------> |  (cmd/rs)                |
|                      |           |                          |
| • /authorize          |          | • /accounts/{id}/orders/ |
| • /token              |          |   export                 |
| • /.well-known/jwks   |          | • Validates JWT, perm,   |
| • RFC 8693 OBO grant  |          |   authorization_details  |
+----------------------+           +--------------------------+
```

- **Authorization Server** – issues authorization codes, user access tokens, client credentials, refresh tokens, and short-lived OBO tokens. Tokens are JWTs with `act`, `perm`, and `authorization_details` claims.
- **Resource Server** – tiny API that expects an OBO token and checks:
  - signature/issuer/audience/expiry,
  - `sub` (human) and `act.actor` (agent),
  - permission string `orders:export:<account-id>`,
  - rich authorization details contain the requested `account-id`.

## Prerequisites

- Go **1.22+**
- `curl`
- Optional: Docker & Docker Compose v2
- Optional: `make` (for helper targets)

## Running locally

```bash
# Install dependencies and build everything
go mod tidy

# Start the authorization server
AS_ISSUER=http://localhost:8080 go run ./cmd/as

# In a second terminal start the resource server
RS_AUDIENCE=http://localhost:9090 go run ./cmd/rs
```

Both services expose `/healthz` endpoints. Defaults are tuned for local development and align with the examples below.

## Running with Docker

```bash
# Build once
docker compose build

# Start the authorization server and demo resource server
docker compose up
```

The compose file publishes:

- Authorization Server: `http://localhost:8080`
- Resource Server: `http://localhost:9090`

Override configuration using environment variables or a local `.env` file (see [Configuration](#configuration)).

## RFC 8693 Token Exchange (On-Behalf-Of) – How to Test

These steps demonstrate a complete OBO delegation flow using only `curl` and the helper tool in `tools/mint_assertion`.

### Step 1 – Obtain a user access token

1. **Request an authorization code** (the server trusts the `X-Demo-User` header as the authenticated human):

   ```bash
   curl -i -G \
     -H "X-Demo-User: user:123" \
     --data-urlencode "response_type=code" \
     --data-urlencode "client_id=client-xyz" \
     --data-urlencode "redirect_uri=http://localhost:8081/callback" \
     --data-urlencode "scope=orders:export" \
     --data-urlencode "state=demo" \
     http://localhost:8080/authorize
   ```

   Inspect the `Location` header for the `code` parameter.

2. **Exchange the code for a user access token**:

   ```bash
   curl -s -u client-xyz:secret-xyz -X POST http://localhost:8080/token \
     -d 'grant_type=authorization_code' \
     --data-urlencode 'code=<AUTH_CODE_FROM_STEP_1>' \
     --data-urlencode 'redirect_uri=http://localhost:8081/callback'
   ```

   Save the `access_token` from the JSON response – that becomes the `subject_token` in the next step.

### Step 2 – Mint an actor client assertion

Use the helper to mint a signed JWT that identifies the agent and controlling OAuth client:

```bash
go run ./tools/mint_assertion \
  -actor agent:ingestor-42 \
  -client client-xyz \
  -audience http://localhost:8080
```

Copy the output (a compact JWT). This is the `actor_token` for token exchange. Adjust the flags to customise the actor ID or execution instance.

### Step 3 – Exchange for an OBO token

```bash
curl -s -u client-xyz:secret-xyz -X POST http://localhost:8080/token \
  -d 'grant_type=urn:ietf:params:oauth:grant-type:token-exchange' \
  --data-urlencode 'subject_token=<USER_ACCESS_TOKEN>' \
  -d 'subject_token_type=urn:ietf:params:oauth:token-type:access_token' \
  --data-urlencode 'actor_token=<ACTOR_ASSERTION_JWT>' \
  -d 'actor_token_type=urn:ietf:params:oauth:token-type:jwt' \
  -d 'audience=http://localhost:9090' \
  --data-urlencode 'authorization_details=[{"type":"agent-action","locations":["http://localhost:9090"],"actions":["orders:export"],"constraints":{"resource_ids":["acct:abc"],"time_limit_sec":900,"max_records":1000,"purpose":"customer_export"}}]'
```

The response contains a short-lived OBO access token with `act`, `perm`, and `authorization_details` claims:

```json
{
  "access_token": "<OBO_JWT>",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "bearer",
  "expires_in": 900,
  "perm": ["orders:export:acct:abc"],
  "authorization_details": [ ... ]
}
```

### Step 4 – Call the resource server

```bash
curl -s \
  -H "Authorization: Bearer <OBO_JWT>" \
  http://localhost:9090/accounts/acct:abc/orders/export
```

Expected response:

```json
{"status":"ok","actor":"agent:ingestor-42","subject":"user:123","resource":"acct:abc"}
```

### Negative testing ideas

- **Wrong account ID** – call `/accounts/acct:evil/orders/export` and expect `403`.
- **Missing `act` claim** – omit the actor token and remove the authenticated client: the server rejects the request.
- **Expired token** – wait for the `exp` to pass (default 15 minutes) or set `AS_OBO_TOKEN_TTL_SECONDS=10` for quick expiry.

### Postman collection

Import the snippet below into Postman. It contains three requests wired together. Configure an environment with variables `AS_BASE`, `RS_BASE`, `USER_TOKEN`, `ACTOR_ASSERTION`, and `OBO_TOKEN` (the tests update these automatically when run sequentially).

```json
{
  "info": {
    "name": "go_oauth2_server OBO demo",
    "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
  },
  "item": [
    {
      "name": "1. Authorization Code",
      "request": {
        "method": "GET",
        "header": [{"key": "X-Demo-User", "value": "user:123"}],
        "url": {
          "raw": "{{AS_BASE}}/authorize?response_type=code&client_id=client-xyz&redirect_uri=http://localhost:8081/callback&scope=orders:export&state=demo",
          "host": ["{{AS_BASE}}"],
          "path": ["authorize"],
          "query": [
            {"key": "response_type", "value": "code"},
            {"key": "client_id", "value": "client-xyz"},
            {"key": "redirect_uri", "value": "http://localhost:8081/callback"},
            {"key": "scope", "value": "orders:export"},
            {"key": "state", "value": "demo"}
          ]
        }
      }
    },
    {
      "name": "2. Token Exchange",
      "request": {
        "method": "POST",
        "auth": {
          "type": "basic",
          "basic": [
            {"key": "username", "value": "client-xyz"},
            {"key": "password", "value": "secret-xyz"}
          ]
        },
        "header": [{"key": "Content-Type", "value": "application/x-www-form-urlencoded"}],
        "url": {"raw": "{{AS_BASE}}/token", "host": ["{{AS_BASE}}"], "path": ["token"]},
        "body": {
          "mode": "urlencoded",
          "urlencoded": [
            {"key": "grant_type", "value": "urn:ietf:params:oauth:grant-type:token-exchange"},
            {"key": "subject_token", "value": "{{USER_TOKEN}}"},
            {"key": "subject_token_type", "value": "urn:ietf:params:oauth:token-type:access_token"},
            {"key": "actor_token", "value": "{{ACTOR_ASSERTION}}"},
            {"key": "actor_token_type", "value": "urn:ietf:params:oauth:token-type:jwt"},
            {"key": "audience", "value": "{{RS_BASE}}"},
            {"key": "authorization_details", "value": "[{\"type\":\"agent-action\",\"locations\":[\"{{RS_BASE}}\"],\"actions\":[\"orders:export\"],\"constraints\":{\"resource_ids\":[\"acct:abc\"],\"purpose\":\"customer_export\"}}]"}
          ]
        }
      }
    },
    {
      "name": "3. Call Resource Server",
      "request": {
        "method": "GET",
        "url": {"raw": "{{RS_BASE}}/accounts/acct:abc/orders/export", "host": ["{{RS_BASE}}"], "path": ["accounts", "acct:abc", "orders", "export"]},
        "header": [{"key": "Authorization", "value": "Bearer {{OBO_TOKEN}}"}]
      }
    }
  ]
}
```

## Automation & scripts

- `make test` – run Go unit tests (currently limited to compilation checks).
- `make test-exchange` – executes `scripts/test_obo.sh` which drives the full code → token → exchange → resource server flow (expects both servers running locally).
- `scripts/test_obo.sh` – reusable bash helper invoked by the make target.

## Configuration

All services read environment variables (see `.env.example`):

| Variable | Description | Default |
| --- | --- | --- |
| `AS_ISSUER` | Issuer URI embedded in all JWTs | `http://localhost:8080` |
| `AS_AUDIENCE` | Default API audience for user/client tokens | `http://localhost:9090` |
| `AS_SIGNING_KEY_BASE64` | Base64 encoded HS256 signing key | `dev-signing-key-1234` |
| `AS_OBO_TOKEN_TTL_SECONDS` | Lifetime for OBO tokens | `900` |
| `AS_DEFAULT_CLIENT_ID` / `AS_DEFAULT_CLIENT_SECRET` | Demo confidential client credentials | `client-xyz` / `secret-xyz` |
| `RS_AUDIENCE` | Expected audience on the resource server | `http://localhost:9090` |

A live JWKS is published at `/.well-known/jwks.json` for convenience so additional services can validate tokens.

## Project layout

```
.
├── cmd
│   ├── as            # Authorization server entry point
│   └── rs            # Demo resource server
├── internal
│   ├── config        # Environment configuration loader
│   ├── jwt           # Signing, verification, and JWKS helpers
│   ├── obo           # Token exchange logic (RAR parsing, ACT claims)
│   └── store         # In-memory client/code/refresh-token store
├── scripts           # bash automation (smoke tests)
├── tools             # Helper utilities (e.g. client assertion minter)
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── .env.example
```

Happy hacking!
