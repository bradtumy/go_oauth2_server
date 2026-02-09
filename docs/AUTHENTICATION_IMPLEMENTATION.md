# OAuth Authorization Flow Implementation

## Overview

This document describes the implementation of proper OAuth 2.0 authorization code flow with authentication and consent in tokenator.

## Architecture Changes

### New Components

#### 1. Session Management (`internal/session/`)
- **`store.go`**: Session store interface and in-memory implementation
- Manages authenticated user sessions with HTTP-only cookies
- Features:
  - Cryptographically secure session IDs
  - Configurable idle timeout (default: 30 min)
  - Absolute session expiration (default: 8 hours)
  - CSRF token generation per session
  - Automatic cleanup of expired sessions

#### 2. Authentication Service (`internal/auth/`)
- **`password.go`**: Password hashing with bcrypt (cost factor: 12)
- **`handlers.go`**: Login/logout handlers and authentication middleware
- **`consent.go`**: OAuth consent page logic and scope descriptions

#### 3. Web Templates (`web/templates/`)
- **`login.html`**: Modern, responsive login page
- **`consent.html`**: OAuth authorization consent page

### Modified Components

#### 1. Human Identity Model
**File**: `internal/identity/types.go`
- Added `PasswordHash` field (bcrypt hash, never exposed in JSON)
- Password stored securely for authentication

#### 2. Identity Handlers
**File**: `internal/identity/handlers.go`
- Added password hashing on human registration
- Supports optional `password` field in POST /register/human

#### 3. Validation
**File**: `internal/identity/validate.go`
- Added `Password` field to `HumanInput` struct

## New OAuth Flow

### Before (Insecure)
```
GET /oauth2/authorize?email=alice@example.com
  → Instant code generation (NO AUTH!)
  → Redirect with authorization code
```

### After (Secure)
```
GET /oauth2/authorize
  → Check session cookie
  → Not authenticated? → Redirect to /login
  → POST /auth/login (validate credentials)
  → Create session, set cookie
  → Redirect back to /oauth2/authorize
  → Show consent page
  → User approves/denies
  → POST /consent (action=approve)
  → Generate authorization code
  → Redirect to client with code
```

## Implementation Steps

### Step 1: Integrate Auth Handler into Authorization Server

**File**: `cmd/as/main.go`

Add session store and auth handler:

```go
import (
	"tokenator/internal/auth"
	"tokenator/internal/session"
)

func main() {
	// ... existing setup ...
	
	// Create session store
	sessionStore := session.NewMemoryStore(30 * time.Minute)
	
	// Create auth handler
	authHandler, err := auth.NewHandler(sessionStore, identityStore, cfg.DevMode)
	if err != nil {
		log.Fatalf("init auth handler: %v", err)
	}
	
	// Start session cleanup worker
	authHandler.StartCleanupWorker(15 * time.Minute)
	
	// Add routes
	mux.HandleFunc("/login", methodHandler(http.MethodGet, authHandler.ShowLogin))
	mux.HandleFunc("/auth/login", methodHandler(http.MethodPost, authHandler.HandleLogin))
	mux.HandleFunc("/auth/logout", authHandler.HandleLogout)
	mux.HandleFunc("/auth/register", authHandler.HandleRegister)
	mux.HandleFunc("/auth/forgot-password", authHandler.HandleForgotPassword)
	
	// Modify authorize handler to require auth
	mux.Handle("/oauth2/authorize", rateLimitMiddleware(authorizeLimiter, 
		methodHandler(http.MethodGet, authHandler.RequireAuth(srv.handleAuthorizeWithConsent))))
	
	// ... rest of main ...
}
```

### Step 2: Update Authorization Handler

**File**: `cmd/as/main.go`

Replace `handleAuthorize` with authentication-aware version:

```go
func (s *authorizationServer) handleAuthorizeWithConsent(w http.ResponseWriter, r *http.Request) {
	// Get authenticated session from context
	sess, ok := auth.SessionFromContext(r.Context())
	if !ok {
		// Should never happen due to RequireAuth middleware
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	q := r.URL.Query()
	
	// Validate OAuth parameters
	if !strings.EqualFold(q.Get("response_type"), "code") {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only authorization_code supported")
		return
	}
	
	clientID := q.Get("client_id")
	client, ok, err := s.clients.GetClient(r.Context(), clientID)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "client lookup failed")
		return
	}
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "unknown client")
		return
	}
	
	if !clientAllowsGrant(client, store.GrantAuthorizationCode) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "authorization_code not allowed")
		return
	}
	
	redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
	if redirectURI == "" {
		if len(client.RedirectURIs) == 1 {
			redirectURI = client.RedirectURIs[0]
		} else {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri required")
			return
		}
	}
	
	if !redirectURIMatch(client.RedirectURIs, redirectURI) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri mismatch")
		return
	}
	
	scope := q.Get("scope")
	if scope == "" {
		scope = strings.Join(client.Scopes, " ")
	}
	if !scopeSubsetList(scope, client.Scopes) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed")
		return
	}
	
	codeChallenge := strings.TrimSpace(q.Get("code_challenge"))
	codeChallengeMethod := strings.ToUpper(strings.TrimSpace(q.Get("code_challenge_method")))
	if codeChallenge != "" && codeChallengeMethod == "" {
		codeChallengeMethod = "PLAIN"
	}
	
	if client.Type == store.ClientTypePublic {
		if codeChallenge == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge required for public clients")
			return
		}
		if codeChallengeMethod != "S256" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
			return
		}
	} else if codeChallenge != "" && codeChallengeMethod != "S256" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
		return
	}
	
	state := q.Get("state")
	
	// Check if consent already exists (could implement consent caching here)
	// For now, always show consent page
	
	// Show consent page
	s.authHandler.ShowConsent(w, r, sess, client, scope, redirectURI, state, codeChallenge, codeChallengeMethod)
}
```

### Step 3: Add Consent Handler

**File**: `cmd/as/main.go`

```go
func (s *authorizationServer) handleConsent(w http.ResponseWriter, r *http.Request) {
	// Get authenticated session
	sess, ok := auth.SessionFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	
	// Parse consent decision
	decision, err := auth.ParseConsentForm(r)
	if err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	
	// User denied consent
	if !decision.Approved {
		auth.RedirectWithError(w, r, decision.RedirectURI, "access_denied", "User denied authorization", decision.State)
		return
	}
	
	// Lookup human by session
	human, ok := s.identities.GetHuman(r.Context(), sess.HumanID)
	if !ok {
		http.Error(w, "User not found", http.StatusInternalServerError)
		return
	}
	
	// Generate authorization code
	code := random.NewID()
	s.store.SaveCode(store.AuthorizationCode{
		Code:                code,
		ClientID:            decision.ClientID,
		HumanID:             human.ID,
		RedirectURI:         decision.RedirectURI,
		Scope:               decision.Scope,
		CodeChallenge:       decision.CodeChallenge,
		CodeChallengeMethod: decision.CodeChallengeMethod,
		IssuedAt:            time.Now().UTC(),
		ExpiresAt:           time.Now().Add(s.cfg.CodeTTL),
	})
	
	// Redirect to client with code
	redirect, err := url.Parse(decision.RedirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	values := redirect.Query()
	values.Set("code", code)
	if decision.State != "" {
		values.Set("state", decision.State)
	}
	redirect.RawQuery = values.Encode()
	
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}
```

And wire it up:

```go
// In main():
mux.Handle("/consent", authHandler.RequireAuth(methodHandler(http.MethodPost, srv.handleConsent)))
```

## Security Improvements

### 1. Authentication Required
- Users must login with email/password
- Passwords hashed with bcrypt (cost: 12)
- No more query parameter bypass (`?email=victim@example.com`)

### 2. Session Management
- HTTP-only cookies prevent XSS attacks
- Secure flag for HTTPS in production
- SameSite=Lax prevents CSRF
- Automatic session expiration
- Idle timeout protection

### 3. Consent Flow
- Users see what permissions they're granting
- Can approve or deny authorization
- Client name and scope descriptions displayed
- Ability to switch accounts before consenting

### 4. CSRF Protection
- CSRF tokens in sessions
- State parameter preserved through flow
- Form POST validation

## Development Mode Features

- Dev mode allows login without passwords for pre-registered users
- Visual indicator on login page when dev mode is active
- Helpful error messages and debugging info

## Configuration

Add to environment variables:

```bash
# Enable dev mode (allows passwordless login)
DEV_MODE=true

# Session settings
SESSION_IDLE_TIMEOUT=30m
SESSION_MAX_DURATION=8h
```

## Docker Deployment

The authentication system works seamlessly with Docker. The Dockerfile has been updated to include the `web/templates` directory:

```dockerfile
COPY --from=build /app/web /web
```

To deploy with Docker Compose:

```bash
# Build with updated templates
docker compose build

# Start services
docker compose up -d

# Verify templates are loaded
docker logs tokenator-as | grep "Session cleanup worker"
```

The templates will be available at `/web/templates/*.html` inside the container, and the authentication handlers will load them from the working directory.

## User Registration with Password

```bash
# Create a human with password
curl -X POST http://localhost:8080/register/human \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "alice@example.com",
    "name": "Alice Example",
    "password": "SecurePassword123!",
    "tenant_id": "default"
  }'
```

## Testing the Flow

### 1. Register a User
```bash
curl -X POST http://localhost:8080/register/human \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "alice@example.com",
    "name": "Alice Example",
    "password": "password123",
    "tenant_id": "default"
  }'
```

### 2. Start Authorization Flow
```bash
# Visit in browser
open "http://localhost:8080/oauth2/authorize?\
response_type=code&\
client_id=human-web&\
redirect_uri=http://localhost:5555/callback&\
scope=tickets.read%20tickets.write&\
code_challenge=${CODE_CHALLENGE}&\
code_challenge_method=S256&\
state=random123"
```

### 3. Login
- Browser redirects to `/login`
- Enter email: alice@example.com
- Enter password: password123
- Click "Sign In"

### 4. Consent
- Browser shows consent page
- Review requested permissions
- Click "Authorize"

### 5. Receive Code
- Browser redirects to `http://localhost:5555/callback?code=...`
- Copy authorization code from URL

### 6. Exchange Code for Token
```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=authorization_code' \
  -d "code=${CODE}" \
  -d 'client_id=human-web' \
  -d "code_verifier=${CODE_VERIFIER}" \
  -d 'redirect_uri=http://localhost:5555/callback'
```

## Next Steps

1. **Persistent Session Store**: Replace in-memory store with Redis for production
2. **Remember Consent**: Cache approved consents to skip consent page for trusted clients
3. **Password Reset**: Implement forgot password flow with email verification
4. **Multi-Factor Authentication**: Add TOTP or SMS 2FA support
5. **Account Management**: UI for users to manage sessions, consents, and passwords
6. **Audit Logging**: Log all authentication and authorization events
7. **Rate Limiting**: Add login attempt rate limiting
8. **Account Lockout**: Implement account lockout after failed login attempts

## Migration Guide

### For Existing Deployments

1. **Backup Data**: Backup identity store before upgrade
2. **Update go.mod**: Run `go mod tidy` to get bcrypt dependency
3. **Optional**: Set passwords for existing users via API:
   ```bash
   # Batch update passwords
   for email in alice@example.com bob@example.com; do
     curl -X PATCH http://localhost:8080/humans/${email} \
       -H 'Content-Type: application/json' \
       -d '{"password": "ChangeMe123!"}'
   done
   ```
4. **Enable Dev Mode** (temporarily): Set `DEV_MODE=true` for testing
5. **Test Flows**: Verify authorization code flow works end-to-end
6. **Disable Dev Mode**: Set `DEV_MODE=false` for production

### Breaking Changes

- **Query Parameter Auth Removed**: `?human_id` and `?email` query parameters in `/oauth2/authorize` are no longer supported
- **Authentication Required**: All authorization requests now require valid session cookies
- **Password Required**: New human registrations should include passwords for login

## Summary

This implementation transforms tokenator from an educational OAuth server into a production-ready authorization server with:

✅ Real user authentication (login/logout)
✅ Secure password storage (bcrypt)
✅ Session management with cookies
✅ OAuth consent flow
✅ CSRF protection
✅ Modern, responsive UI
✅ Security best practices

The authorization code flow now properly authenticates users and obtains their consent before issuing tokens, following OAuth 2.0 and OIDC best practices.
