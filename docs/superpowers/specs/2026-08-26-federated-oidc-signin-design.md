# Federated Sign-In via an Upstream OIDC Provider

**Date:** 2026-08-26
**Status:** Approved, ready for implementation planning
**Author:** Brad Tumy (design session with Claude)

## Summary

Let people sign in to tokenator with Google instead of a password. Google
authenticates the human; tokenator continues to mint its own tokens for agent
clients. A person who has never signed in before gets a local profile created
for them on the spot, and that profile is reused on every later sign-in.

This makes tokenator an identity broker: an OIDC relying party facing Google,
and an authorization server facing its own clients.

## Problem

Human identities live in an in-memory store that is reseeded on every boot.
Getting a person into the system today means either editing `seed/identities.json`
or calling `POST /register/human` by hand, and every account needs a password
that someone has to distribute. The login page advertised self-service
registration for months via a link to `/auth/register`, an endpoint that was
never implemented.

Federated sign-in removes the password distribution problem: testers use an
account they already have, and their profile is created on first use.

## Goals

- Sign in with Google, with no tokenator-specific password.
- First sign-in creates a local profile; later sign-ins reuse it.
- Password login keeps working for seeded accounts and scripted tests.
- Adding a second upstream provider is a configuration change, not new code.

## Non-goals

- Self-service password registration. It does not exist today and is not being
  added; account creation is federated sign-in or the seed file.
- Linking more than one upstream provider to a single local profile.
- Persisting human identities. They remain in memory (see Known limitations).
- Replacing the parked Trusted Auth Token work. Unrelated protocol.

## Decisions

| Decision | Choice | Why |
|---|---|---|
| Password login | Coexists | Automated tests cannot traverse Google's consent screen. Removing passwords would break `scripts/` and the Go suite, or force a test-only auth bypass — the exact shortcut recently removed from `handleAuthorize`. |
| Account matching | Google `sub`, adopting verified email on first sign-in | `sub` is stable across email changes. Matching on email alone lets whoever controls a matching Google account inherit a local profile. |
| Provider scope | Generic upstream provider; Google is config | OIDC discovery does the work, so the generic form is barely more code, and another IdP becomes env vars. |
| OIDC client | `golang.org/x/oauth2` + `github.com/coreos/go-oidc/v3` | Verifying a third party's ID tokens is security-critical code with subtle failure modes. go-oidc is the reference implementation. |

## Architecture

Two units with a clean seam between protocol and policy.

### `internal/federation`

Speaks OIDC. Knows nothing about tokenator's identity model.

```go
type Config struct {
    Issuer       string
    ClientID     string
    ClientSecret string
    RedirectURL  string
    Scopes       []string
}

type Claims struct {
    Subject       string
    Email         string
    EmailVerified bool
    Name          string
}

func New(ctx context.Context, cfg Config) (*Provider, error)
func (p *Provider) AuthCodeURL(state, nonce string) string
func (p *Provider) Exchange(ctx context.Context, code, nonce string) (Claims, error)
```

`Exchange` swaps the code for tokens and verifies the ID token — issuer,
audience, expiry, signature, and nonce — before returning normalized claims.
Callers never see a raw token.

### `internal/auth/federated.go`

Owns the HTTP handlers and the identity decision. Depends on `federation` and
`identity.Store`; contains no OIDC protocol logic.

- `HandleSSOStart` — `GET /auth/sso/login`
- `HandleSSOCallback` — `GET /auth/sso/callback`
- `resolveFederatedHuman(ctx, Claims) (identity.Human, error)` — a pure decision
  function, table-testable without any HTTP or network.

## Data flow

```
/login  →  [ Sign in with Google ]  →  GET /auth/sso/login
    ├── mint state + nonce, store in HttpOnly SameSite=Lax cookies (single use, 10 min)
    └── 302 to the provider's authorization endpoint

provider  →  GET /auth/sso/callback?code=…&state=…
    ├── state matches cookie?            no → 400
    ├── exchange code for tokens
    ├── verify ID token (iss, aud, exp, signature, nonce)
    ├── email_verified true?             no → /login?error=…
    ├── resolve identity                 (below)
    ├── session.Create(human.ID, human.Email)
    └── 302 to return_to
```

`RequireAuth` already redirects unauthenticated users to `/login?return_to=…`,
so an agent's authorization request resumes on its own once sign-in completes.

### Identity resolution

In order:

1. `GetHumanByFederatedSubject("google:" + sub)` hits — use that profile.
2. Otherwise, if `email_verified` and `GetHumanByEmail(email)` hits — **link**:
   stamp `FederatedSubject` on the existing profile and keep its ID.
3. Otherwise **create** a profile from sub, email, and name, with no password.

An unverified email never links and never creates. It is rejected outright.

## Data model

`identity.Human` gains one field:

```go
FederatedSubject string `json:"-"` // provider-qualified, e.g. "google:1234567890"
```

`identity.Store` gains one method:

```go
GetHumanByFederatedSubject(ctx context.Context, subject string) (Human, bool)
```

`internal/store/mem/store.go` is the only implementation, and maintains a
`map[string]string` from federated subject to human ID alongside its existing
email index.

The field is `json:"-"`: the upstream subject is an internal correlator and is
not exposed through `/humans`.

## Configuration

```
UPSTREAM_ISSUER=https://accounts.google.com
UPSTREAM_CLIENT_ID=
UPSTREAM_CLIENT_SECRET=
UPSTREAM_SCOPES=openid,email,profile
UPSTREAM_DISPLAY_NAME=Google
PUBLIC_BASE_URL=http://localhost:8080
```

The redirect URI is `{PUBLIC_BASE_URL}/auth/sso/callback`. The path is
provider-neutral because the component is generic; Google Cloud must be
configured with this exact string.

Secrets reach the container through compose `${VAR}` interpolation, which reads
the gitignored `.env` automatically. No new `env_file` wiring and no secrets in
git.

**Absent configuration disables the feature**: no button renders, the routes
return 404, and the login page is unchanged. Configuration is considered present
when issuer, client ID, and client secret are all non-empty.

## Error handling

Discovery is a network call at startup. It must **not** be fatal — an
unreachable provider would otherwise make the authorization server unbootable
and take down password login with it. Startup attempts discovery under a
timeout; on failure it logs a warning, leaves federation disabled, and retries
lazily on the first `/auth/sso/login`.

| Condition | Response |
|---|---|
| Provider returns `error` | 302 `/login?error=<provider message>` |
| Missing or mismatched state | 400, logged as a possible CSRF attempt |
| ID token fails verification | 302 `/login?error=Sign-in failed` |
| `email_verified` false | 302 `/login?error=Your provider did not verify this email address` |
| Discovery unavailable | Feature disabled, password login unaffected |

## Security

- **State** is a CSRF defense; **nonce** is a replay defense bound into the ID
  token. Both are single-use, random, and required.
- **`return_to` is validated as a relative path.** Absolute URLs are rejected,
  closing an open-redirect that would otherwise let a crafted login link bounce
  a freshly authenticated user to an attacker's site.
- **Unverified emails never link.** This is what prevents a Google account from
  claiming a local profile it does not own.
- Cookies are `HttpOnly` with `SameSite=Lax`, scoped to the callback path, and
  cleared on use. `Secure` follows the existing session cookie's behavior.
- Only sub, email, and name are stored. Upstream access and refresh tokens are
  used for the exchange and discarded — tokenator has no need to call Google
  APIs on the user's behalf.

## Testing

- **Fake issuer integration test.** An `httptest` server serves an OIDC
  discovery document and JWKS, and signs ID tokens with a test key. The full
  callback runs against it, exercising real verification with no network access
  and no Google account.
- **Resolution table tests** on `resolveFederatedHuman`: match by subject, link
  by verified email, JIT create, reject unverified email, and the collision case
  where an unverified email must *not* link to a matching local profile.
- **Open-redirect test**: an absolute `return_to` is rejected.
- **State and nonce tests**: missing, mismatched, and replayed values all fail.
- **Coexistence**: the existing password login tests are untouched and must
  continue to pass.

No test contacts Google.

## Setup

1. Google Cloud console → APIs & Services → Credentials → Create OAuth client ID
   → Web application.
2. Authorized redirect URI: `http://localhost:8080/auth/sso/callback`.
3. Put the client ID and secret in `.env` (already gitignored).
4. `docker compose up -d --build`.

## Known limitations

Human identities are in memory, so a JIT-created profile disappears on restart
and is recreated on the next sign-in with a **new** `Human.ID`. Anything that
persists a human ID — grants, consent records — would dangle across a restart.
Seeded accounts are unaffected because they are recreated with the same data
each boot. Persisting identities is a separate piece of work.

## Risks

| Risk | Mitigation |
|---|---|
| Provider outage blocks all sign-in | Password login coexists; discovery failure degrades instead of crashing |
| Redirect URI mismatch (common setup error) | Exact string documented above and in `.env.example`; log the computed redirect URI at startup |
| JIT profiles diverge from seeded ones | Verified-email linking adopts the seeded profile rather than duplicating it |
| Unstable human IDs across restarts | Documented; nothing currently persists human IDs |
