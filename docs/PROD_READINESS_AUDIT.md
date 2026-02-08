# Production Readiness Audit Report

## Current State Summary

### Entry points
- **Authorization Server (AS):** `cmd/as/main.go` starts the AS, registers HTTP routes for OAuth, identity registration, and JWKS, and starts the admin API listener on a separate address.【F:cmd/as/main.go†L26-L121】
- **Resource Server (RS):** `cmd/rs/main.go` starts the RS and exposes a single protected resource endpoint, plus `/healthz`.【F:cmd/rs/main.go†L17-L86】
- **CLI tooling:** `cmd/seed-clients/main.go` seeds OAuth clients into the configured client store.【F:cmd/seed-clients/main.go†L1-L162】

### Endpoints implemented
**Authorization Server (port 8080 by default)**
- `/.well-known/jwks.json` (JWKS)【F:cmd/as/main.go†L77-L264】
- `/authorize` and `/oauth2/authorize` (authorization code)【F:cmd/as/main.go†L78-L83】【F:cmd/as/main.go†L266-L347】
- `/token` and `/oauth2/token` (token endpoint supporting multiple grants)【F:cmd/as/main.go†L79-L84】【F:cmd/as/main.go†L350-L392】
- `/subject-assertion` and `/mint-assertion` (subject assertion JWTs)【F:cmd/as/main.go†L82-L83】【F:cmd/as/main.go†L394-L449】
- Identity registration APIs:
  - `/register/human`, `/register/agent` (create)【F:cmd/as/main.go†L84-L85】
  - `/humans`, `/agents` (list)【F:cmd/as/main.go†L86-L87】
  - `/humans/{id}`, `/agents/{id}` (get/delete)【F:cmd/as/main.go†L88-L109】
- `/healthz` (health check)【F:cmd/as/main.go†L73-L76】
- `/oauth2/introspect` (token introspection)【F:cmd/as/main.go†L86-L90】【F:cmd/as/main.go†L396-L469】
- `/oauth2/revoke` (token revocation)【F:cmd/as/main.go†L87-L90】【F:cmd/as/main.go†L471-L499】

**Admin API (bound to `AS_ADMIN_ADDR`, default `127.0.0.1:8082`)**
- `GET/POST /admin/clients` (list/create)【F:cmd/as/main.go†L116-L120】【F:internal/admin/clients.go†L19-L68】
- `GET/PUT/DELETE /admin/clients/{client_id}` (get/update/delete)【F:cmd/as/main.go†L116-L120】【F:internal/admin/clients.go†L70-L158】

**Resource Server (port 9090 by default)**
- `GET /accounts/{id}/orders/export` (protected OBO resource)【F:cmd/rs/main.go†L29-L72】
- `/healthz` (health check)【F:cmd/rs/main.go†L28-L33】

**Not implemented**
- `/.well-known/openid-configuration` (OIDC discovery) is not present in the codebase (only JWKS is served).【F:cmd/as/main.go†L73-L83】

### Supported grants
- `authorization_code`【F:cmd/as/main.go†L360-L382】
- `refresh_token`【F:cmd/as/main.go†L360-L382】
- `client_credentials`【F:cmd/as/main.go†L360-L382】
- `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693 shaped)【F:cmd/as/main.go†L360-L383】【F:cmd/as/main.go†L551-L676】

### Storage model
- **Authorization codes:** in-memory map in `internal/store.Store` (not persisted).【F:internal/store/store.go†L18-L65】
- **Refresh tokens:** in-memory map in `internal/store.Store` (not persisted).【F:internal/store/store.go†L18-L86】
- **Clients:** in-memory or sqlite-backed client store (`AS_CLIENT_STORE` / `AS_CLIENTS_DB`).【F:cmd/as/main.go†L25-L47】【F:cmd/as/main.go†L662-L688】【F:internal/store/mem/client_store.go†L11-L73】【F:internal/store/sqlite/client_store.go†L16-L113】
- **Identities (humans/agents):** in-memory identity store (`internal/store/mem` for identity storage), optionally seeded from JSON at startup (`SEED_IDENTITIES_JSON`).【F:cmd/as/main.go†L33-L58】【F:cmd/as/main.go†L730-L842】

### Key management
- **Key source:** RSA private key loaded from `AS_SIGNING_KEY_PEM`/`AS_SIGNING_KEY_PATH` (single key) or from `AS_SIGNING_KEYS_DIR` (multi-key) with `AS_SIGNING_KEY_ID` selecting the active `kid`.【F:internal/config/config.go†L79-L205】【F:internal/jwt/keyset.go†L20-L101】
- **JWKS:** publishes all loaded RSA public keys with `kid`, `alg=RS256`, `use=sig` for overlap during rotation.【F:internal/jwt/issuer.go†L205-L253】
- **Rotation:** optional key reload via `AS_SIGNING_KEY_ROTATION_SECONDS` (disabled by default), enabling key overlap without downtime.【F:internal/config/config.go†L109-L139】【F:cmd/as/main.go†L1150-L1178】

### Security controls (current)
- **Redirect URI validation:** exact string match against client-registered redirect URIs; required when multiple URIs exist.【F:cmd/as/main.go†L284-L315】【F:cmd/as/main.go†L690-L699】
- **Authorization code TTL and one-time use:** codes are stored with an expiry and consumed on use, with PKCE binding for public clients.【F:cmd/as/main.go†L323-L341】【F:cmd/as/main.go†L451-L510】【F:internal/store/store.go†L18-L67】
- **PKCE enforcement:** S256 PKCE is required for public clients; `code_verifier` is validated on token exchange.【F:cmd/as/main.go†L323-L341】【F:cmd/as/main.go†L461-L510】
- **Client authentication:** confidential clients require a matching secret; public clients can use client_id only.【F:cmd/as/main.go†L606-L655】
- **Refresh token rotation:** refresh tokens rotate on use and reuse revokes the token family.【F:cmd/as/main.go†L506-L577】【F:internal/store/store.go†L67-L150】
- **Access token claims:** issuer/audience/exp/iat/nbf/jti are set; tokens are RS256-signed with `kid`.【F:internal/jwt/issuer.go†L96-L177】
- **Token verification (RS):** verifies signature, issuer, audience, expiry/nbf, and rejects non-RS256 headers or unknown `kid` values.【F:internal/jwt/issuer.go†L181-L254】【F:cmd/rs/main.go†L105-L151】
- **Rate limiting:** token bucket limits for authorize/token/introspect/admin endpoints (configurable).【F:cmd/as/main.go†L70-L121】【F:cmd/as/main.go†L642-L662】
- **State/CSRF:** `state` is passed through but not validated or required (still a gap for browser flows).【F:cmd/as/main.go†L266-L356】
- **Logging:** basic request timing logs in AS; admin changes logged as JSON; no request ID or structured logging across the board.【F:cmd/as/main.go†L628-L640】【F:internal/admin/clients.go†L177-L205】

## Gaps & Risks (Prioritized)

### P0 — Must-fix before production
1. **State/CSRF protection gaps**: `state` is not required or validated, which is risky for browser-based authorization flows.【F:cmd/as/main.go†L266-L356】
2. **Access token revocation is not enforced**: JWT access tokens remain valid until expiry (no blacklist), so revocation only applies to refresh tokens.【F:cmd/as/main.go†L471-L499】【F:cmd/as/main.go†L506-L577】

### P1 — Should-fix next
1. **Structured request/audit logging with request_id** is missing; current logs are not structured and lack correlation identifiers.【F:cmd/as/main.go†L628-L640】
2. **Metrics/health telemetry** not provided beyond `/healthz`; no metrics endpoint or integration docs.
3. **Admin endpoint hardening**: admin API relies solely on bearer token, bound to localhost but no mTLS or explicit allowlist; needs rate limiting and more rigorous auth hardening.【F:cmd/as/main.go†L110-L121】【F:internal/admin/clients.go†L19-L126】
4. **Configuration validation** is limited (no warnings on dev key usage or insecure defaults); prod safe defaults are not enforced.【F:internal/config/config.go†L79-L205】
5. **HA/storage concerns**: codes and refresh tokens remain in memory, limiting HA and crash recovery scenarios.【F:internal/store/store.go†L18-L150】

### P2 — Later / out-of-scope for this pass
1. **High availability and statelessness**: codes/refresh tokens stored in memory; no HA replication strategy. Needs shared storage (DB/redis) or stateless approach.
2. **OIDC conformance**: no discovery document, ID token support, or OIDC claims strategy.
3. **Sender-constrained tokens (DPoP/mTLS)** are not implemented; only bearer tokens are used.
4. **Database migration tooling** for sqlite client store is not present; schema changes require manual intervention.【F:internal/store/sqlite/client_store.go†L25-L60】
