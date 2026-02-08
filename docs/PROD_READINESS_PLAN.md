# Production Readiness Change Plan

## P0 (must implement now)
**What**
- Harden authorization code flow: enforce PKCE S256, bind codes to client_id/redirect_uri/code_challenge/scopes, and enforce one-time use + TTL.
- Implement refresh token rotation with reuse detection and family revocation; if not feasible, disable refresh tokens and document.
- Enforce strict client authentication on `/oauth2/token` for confidential clients.
- Implement `/oauth2/revoke` and `/oauth2/introspect` (or clearly document limitations if minimal semantics).
- Add rate limiting for `/oauth2/authorize`, `/oauth2/token`, `/oauth2/introspect`, and `/admin/*`.
- Key management improvements: configurable key loading, JWKS with `kid`, and rotation scaffolding with overlap support; restrict algorithms to RS256 only.

**Why**
- These are critical protocol correctness and security hardening items required for production OAuth deployments.

**Risk**
- Medium: changes affect token issuance and may break existing dev integrations; must add tests and document configuration changes.

**Tests**
- `go test ./...`
- New unit tests covering PKCE validation, code binding, refresh rotation/reuse detection, revocation/introspection, and rate limiting.

## P1 (next)
**What**
- Add structured JSON logging with request_id propagation.
- Add an audit log stream for security events (token issuance, refresh reuse, revocation, admin changes).
- Add `/metrics` endpoint (Prometheus) or document integration hooks if not feasible in this pass.
- Harden admin API authentication (stronger auth, stricter validation, rate limiting, and/or localhost binding checks).

**Why**
- Improves observability, auditability, and operational readiness.

**Risk**
- Low to medium: mostly additive but may require new config.

**Tests**
- Unit tests validating request_id presence and audit logging behavior (if structured logging is added).

## P2 (later)
**What**
- HA guidance and statelessness notes (shared DB/redis for codes/refresh tokens).
- Sender-constrained tokens (DPoP/mTLS) if required.
- Deeper OIDC conformance (discovery, ID tokens, claims).
- Formal migration strategy for client/identity storage.

**Why**
- These are larger features and operational concerns that require a broader design effort.

**Risk**
- Medium to high depending on implementation depth.

**Tests**
- Integration tests in a staged environment with multi-node setups.

## Out of scope for this pass
- Full HA architecture design and implementation.
- Full OIDC certification and conformance suite.
- DPoP or mTLS sender-constrained token support.
- Multi-tenant policy engine / complex consent flows.

