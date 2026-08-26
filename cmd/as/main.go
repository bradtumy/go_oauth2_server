package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"tokenator/internal/admin"
	"tokenator/internal/auth"
	"tokenator/internal/config"
	"tokenator/internal/identity"
	internaljwt "tokenator/internal/jwt"
	"tokenator/internal/obo"
	"tokenator/internal/random"
	"tokenator/internal/ratelimit"
	"tokenator/internal/session"
	"tokenator/internal/store"
	memstore "tokenator/internal/store/mem"
	sqlstore "tokenator/internal/store/sqlite"
)

func main() {
	loadDotEnv()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	logConfiguration(cfg)

	st := store.New()
	clientStore, err := buildClientStore(cfg)
	if err != nil {
		log.Fatalf("init client store: %v", err)
	}

	identityStore := memstore.New()
	if cfg.SeedIdentitiesPath != "" {
		if err := seedIdentities(context.Background(), identityStore, cfg.SeedIdentitiesPath); err != nil {
			log.Fatalf("seed identities: %v", err)
		}
	}

	// Initialize session store with 30 minute idle timeout
	sessionStore := session.NewMemoryStore(30 * time.Minute)

	// Initialize authentication handler
	authHandler, err := auth.NewHandler(sessionStore, identityStore, cfg.DevMode)
	if err != nil {
		log.Fatalf("init auth handler: %v", err)
	}

	// Start session cleanup worker (runs every 15 minutes)
	authHandler.StartCleanupWorker(15 * time.Minute)
	log.Printf("Session cleanup worker started (interval: 15m, idle timeout: 30m)")

	signer, err := buildSigner(cfg)
	if err != nil {
		log.Fatalf("init signer: %v", err)
	}
	if cfg.SigningKeyDir != "" && cfg.SigningKeyRotationInterval > 0 {
		startKeyRotation(cfg, signer)
	}
	oboService := &obo.Service{Signer: signer, Issuer: cfg.Issuer, Audience: cfg.Audience, OBOTTL: cfg.OBOTokenTTL}

	// RFC 7523 & RFC 9449: Initialize JTI store for replay protection
	jtiStore := store.NewJTIStore()
	log.Printf("JTI store initialized for RFC 7523 (JWT assertions) and RFC 9449 (DPoP) replay protection")

	srv := &authorizationServer{
		cfg:                cfg,
		store:              st,
		clients:            clientStore,
		signer:             signer,
		oboService:         oboService,
		identities:         identityStore,
		authHandler:        authHandler,
		jtiStore:           jtiStore,
		allowLegacy:        cfg.AllowLegacy,
		legacyUsers:        map[string]string{"user:123": "demo-user"},
		legacyDefaultHuman: "user:123",
	}

	identityHandler := identity.NewHandler(identityStore, cfg.AdminToken)
	authorizeLimiter := ratelimit.NewLimiter(float64(cfg.AuthorizeRateLimitRPS), cfg.AuthorizeRateLimitBurst)
	tokenLimiter := ratelimit.NewLimiter(float64(cfg.TokenRateLimitRPS), cfg.TokenRateLimitBurst)
	introspectLimiter := ratelimit.NewLimiter(float64(cfg.IntrospectRateLimitRPS), cfg.IntrospectRateLimitBurst)
	adminLimiter := ratelimit.NewLimiter(float64(cfg.AdminRateLimitRPS), cfg.AdminRateLimitBurst)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", methodHandler(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	}))
	mux.Handle("/.well-known/jwks.json", methodHandler(http.MethodGet, srv.handleJWKS))
	mux.Handle("/.well-known/oauth-authorization-server", methodHandler(http.MethodGet, srv.handleAuthorizationServerMetadata))
	mux.Handle("/.well-known/openid-configuration", methodHandler(http.MethodGet, srv.handleOpenIDConfiguration))

	// Authentication routes
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			authHandler.ShowLogin(w, r)
		} else if r.Method == http.MethodPost {
			authHandler.HandleLogin(w, r)
		} else {
			methodNotAllowed(w, r, http.MethodGet, http.MethodPost)
		}
	})
	mux.HandleFunc("/logout", authHandler.HandleLogout)
	mux.Handle("/consent", authHandler.RequireAuth(methodHandler(http.MethodPost, srv.handleConsent)))

	// OAuth routes with authentication required
	mux.Handle("/authorize", rateLimitMiddleware(authorizeLimiter, authHandler.RequireAuth(methodHandler(http.MethodGet, srv.handleAuthorize))))
	mux.Handle("/token", rateLimitMiddleware(tokenLimiter, methodHandler(http.MethodPost, srv.handleToken)))
	mux.Handle("/oauth2/authorize", rateLimitMiddleware(authorizeLimiter, authHandler.RequireAuth(methodHandler(http.MethodGet, srv.handleAuthorize))))
	mux.Handle("/oauth2/token", rateLimitMiddleware(tokenLimiter, methodHandler(http.MethodPost, srv.handleToken)))
	mux.Handle("/oauth2/introspect", rateLimitMiddleware(introspectLimiter, methodHandler(http.MethodPost, srv.handleIntrospect)))
	mux.Handle("/oauth2/revoke", rateLimitMiddleware(tokenLimiter, methodHandler(http.MethodPost, srv.handleRevoke)))
	mux.HandleFunc("/mint-assertion", methodHandler(http.MethodPost, srv.handleSubjectAssertion))
	mux.HandleFunc("/subject-assertion", methodHandler(http.MethodPost, srv.handleSubjectAssertion))
	mux.HandleFunc("/register/human", methodHandler(http.MethodPost, identityHandler.CreateHuman))
	mux.HandleFunc("/register/agent", methodHandler(http.MethodPost, identityHandler.CreateAgent))
	mux.HandleFunc("/humans", methodHandler(http.MethodGet, identityHandler.ListHumans))
	mux.HandleFunc("/agents", methodHandler(http.MethodGet, identityHandler.ListAgents))
	mux.HandleFunc("/humans/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			identityHandler.GetHuman(w, r)
		case http.MethodDelete:
			identityHandler.DeleteHuman(w, r)
		default:
			methodNotAllowed(w, r, http.MethodGet, http.MethodDelete)
		}
	})
	mux.HandleFunc("/agents/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			identityHandler.GetAgent(w, r)
		case http.MethodDelete:
			identityHandler.DeleteAgent(w, r)
		default:
			methodNotAllowed(w, r, http.MethodGet, http.MethodDelete)
		}
	})

	addr := ":8080"
	if v := os.Getenv("AS_LISTEN_ADDR"); v != "" {
		addr = v
	}

	adminHandler := admin.NewClientHandler(clientStore, cfg.AdminToken)
	adminMux := http.NewServeMux()
	adminMux.HandleFunc("/admin/clients", adminHandler.HandleClients)
	adminMux.HandleFunc("/admin/clients/", adminHandler.HandleClient)
	adminHandlerWithLimit := rateLimitMiddleware(adminLimiter, adminMux)

	go func() {
		log.Printf("Admin API listening on %s", cfg.AdminAddr)
		if err := http.ListenAndServe(cfg.AdminAddr, loggingMiddleware(adminHandlerWithLimit)); err != nil {
			log.Fatalf("admin listen: %v", err)
		}
	}()

	log.Printf("Authorization server listening on %s", addr)
	if err := http.ListenAndServe(addr, loggingMiddleware(mux)); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

type authorizationServer struct {
	cfg                *config.Config
	store              *store.Store
	clients            store.ClientStore
	signer             *internaljwt.Signer
	oboService         *obo.Service
	identities         identity.Store
	authHandler        *auth.Handler
	jtiStore           *store.JTIStore // RFC 7523 & RFC 9449: Replay protection
	allowLegacy        bool
	legacyUsers        map[string]string
	legacyDefaultHuman string
}

var (
	errHumanSelectionRequired = errors.New("human selection required")
	errAgentAmbiguous         = errors.New("multiple agents registered for client; specify agent_id")
	errAgentClientMismatch    = errors.New("agent client_id does not match authenticated client")
)

func (s *authorizationServer) resolveHumanSelection(ctx context.Context, humanID, email string) (identity.Human, error) {
	humanID = strings.TrimSpace(humanID)
	email = strings.TrimSpace(email)
	if humanID != "" {
		return s.lookupHumanByID(ctx, humanID)
	}
	if email != "" {
		if human, ok := s.identities.GetHumanByEmail(ctx, email); ok {
			return human, nil
		}
		return identity.Human{}, identity.ErrHumanNotFound
	}
	if s.allowLegacy && s.legacyDefaultHuman != "" {
		if human, ok := s.legacyHuman(s.legacyDefaultHuman); ok {
			return human, nil
		}
	}
	return identity.Human{}, errHumanSelectionRequired
}

func (s *authorizationServer) lookupHumanByID(ctx context.Context, id string) (identity.Human, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return identity.Human{}, identity.ErrHumanNotFound
	}
	if human, ok := s.identities.GetHuman(ctx, id); ok {
		return human, nil
	}
	if s.allowLegacy {
		if human, ok := s.legacyHuman(id); ok {
			return human, nil
		}
	}
	return identity.Human{}, identity.ErrHumanNotFound
}

func (s *authorizationServer) legacyHuman(id string) (identity.Human, bool) {
	name, ok := s.legacyUsers[id]
	if !ok {
		return identity.Human{}, false
	}
	return identity.Human{
		ID:       id,
		Name:     name,
		TenantID: "legacy",
	}, true
}

func (s *authorizationServer) humanExtraClaims(h identity.Human) map[string]any {
	claims := make(map[string]any)
	if h.Email != "" {
		claims["email"] = h.Email
	}
	if h.Name != "" {
		claims["name"] = h.Name
	}
	if h.TenantID != "" {
		claims["tenant_id"] = h.TenantID
	}
	if len(h.Attributes) > 0 {
		claims["human_attributes"] = h.Attributes
	}
	if len(claims) == 0 {
		return nil
	}
	return claims
}

func (s *authorizationServer) resolveAgent(ctx context.Context, clientID, requestedAgentID string, claim obo.ActClaim) (identity.Agent, error) {
	clientID = strings.TrimSpace(clientID)
	requestedAgentID = strings.TrimSpace(requestedAgentID)
	if claim.ClientID != "" && clientID != "" && !strings.EqualFold(claim.ClientID, clientID) {
		return identity.Agent{}, errAgentClientMismatch
	}
	if requestedAgentID != "" {
		if agent, ok := s.identities.GetAgentByLabel(ctx, clientID, requestedAgentID); ok {
			return agent, nil
		}
		if agent, ok := s.identities.GetAgent(ctx, requestedAgentID); ok && strings.EqualFold(agent.ClientID, clientID) {
			return agent, nil
		}
		return identity.Agent{}, identity.ErrAgentNotFound
	}
	if claim.Actor != "" {
		if agent, ok := s.identities.GetAgent(ctx, claim.Actor); ok {
			if !strings.EqualFold(agent.ClientID, clientID) {
				return identity.Agent{}, errAgentClientMismatch
			}
			return agent, nil
		}
		if agent, ok := s.identities.GetAgentByLabel(ctx, clientID, claim.Actor); ok {
			return agent, nil
		}
	}
	agents, err := s.identities.ListAgentsByClient(ctx, clientID)
	if err != nil {
		return identity.Agent{}, err
	}
	if len(agents) == 0 {
		return identity.Agent{}, identity.ErrAgentNotFound
	}
	if len(agents) > 1 {
		return identity.Agent{}, errAgentAmbiguous
	}
	return agents[0], nil
}

func (s *authorizationServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.signer.JWKS()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, jwks)
}

// clientAssertionAlgValues are the algorithms accepted for RFC 7523 private_key_jwt
// client assertions, matching the key types auth.ValidatePublicKey will parse.
var clientAssertionAlgValues = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}

// dpopAlgValues are the algorithms accepted on RFC 9449 DPoP proofs. Proof keys
// arrive as a JWK in the header, so both RSA and EC signatures are verifiable.
var dpopAlgValues = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

func (s *authorizationServer) handleAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimSpace(s.cfg.MetadataIssuer)
	if issuer == "" {
		issuer = strings.TrimSpace(s.cfg.Issuer)
	}
	issuer = strings.TrimRight(issuer, "/")

	metadata := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/oauth2/authorize",
		"token_endpoint":                        issuer + "/oauth2/token",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"introspection_endpoint":                issuer + "/oauth2/introspect",
		"revocation_endpoint":                   issuer + "/oauth2/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"token_endpoint_auth_signing_alg_values_supported": clientAssertionAlgValues,
		"dpop_signing_alg_values_supported":                dpopAlgValues,
		"code_challenge_methods_supported":                 []string{"S256"},
		"scopes_supported":                                 []string{"openid", "orders:read", "orders:export"},
	}

	writeJSON(w, http.StatusOK, metadata)
}

func (s *authorizationServer) handleOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	issuer := strings.TrimSpace(s.cfg.MetadataIssuer)
	if issuer == "" {
		issuer = strings.TrimSpace(s.cfg.Issuer)
	}
	issuer = strings.TrimRight(issuer, "/")

	metadata := map[string]any{
		"issuer":                                           issuer,
		"authorization_endpoint":                           issuer + "/oauth2/authorize",
		"token_endpoint":                                   issuer + "/oauth2/token",
		"jwks_uri":                                         issuer + "/.well-known/jwks.json",
		"response_types_supported":                         []string{"code"},
		"grant_types_supported":                            []string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"subject_types_supported":                          []string{"public"},
		"id_token_signing_alg_values_supported":            []string{"RS256"},
		"scopes_supported":                                 []string{"openid", "orders:read", "orders:export"},
		"token_endpoint_auth_methods_supported":            []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		"token_endpoint_auth_signing_alg_values_supported": clientAssertionAlgValues,
		"dpop_signing_alg_values_supported":                dpopAlgValues,
		"code_challenge_methods_supported":                 []string{"S256"},
	}

	writeJSON(w, http.StatusOK, metadata)
}

func (s *authorizationServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// Get authenticated session from context (RequireAuth middleware ensures this exists)
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

	// Show consent page (user must approve before we issue a code)
	s.authHandler.ShowConsent(w, r, sess, client, scope, redirectURI, state, codeChallenge, codeChallengeMethod)
}

func (s *authorizationServer) handleConsent(w http.ResponseWriter, r *http.Request) {
	// Get authenticated session (RequireAuth middleware ensures this exists)
	sess, ok := auth.SessionFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Parse consent decision from form
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	action := r.PostFormValue("action")
	clientID := r.PostFormValue("client_id")
	redirectURI := r.PostFormValue("redirect_uri")
	scope := r.PostFormValue("scope")
	state := r.PostFormValue("state")
	codeChallenge := r.PostFormValue("code_challenge")
	codeChallengeMethod := r.PostFormValue("code_challenge_method")

	// User denied consent
	if action != "approve" {
		auth.RedirectWithError(w, r, redirectURI, "access_denied", "User denied authorization", state)
		return
	}

	// User approved - generate authorization code
	code := random.NewID()
	s.store.SaveCode(store.AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		HumanID:             sess.HumanID,
		RedirectURI:         redirectURI,
		Scope:               scope,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		IssuedAt:            time.Now().UTC(),
		ExpiresAt:           time.Now().Add(s.cfg.CodeTTL),
	})

	// Redirect to client with code
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}
	values := redirect.Query()
	values.Set("code", code)
	if state != "" {
		values.Set("state", state)
	}
	redirect.RawQuery = values.Encode()

	w.Header().Set("Location", redirect.String())
	w.WriteHeader(http.StatusFound)
}

func (s *authorizationServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("[OAUTH_FLOW] ✗ Unable to parse form: %v", err)
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unable to parse form")
		return
	}

	grantType := r.PostFormValue("grant_type")
	log.Printf("[OAUTH_FLOW] → Token request: grant_type=%s", grantType)

	client, err := s.authenticateClient(r, grantType)
	if err != nil {
		log.Printf("[AUTH] ✗ Client authentication failed: %v", err)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	log.Printf("[AUTH] ✓ Client authenticated: client_id=%s", client.ID)

	switch grantType {
	case "authorization_code":
		s.handleAuthorizationCodeGrant(w, r, client)
	case "refresh_token":
		s.handleRefreshTokenGrant(w, r, client)
	case "client_credentials":
		s.handleClientCredentialsGrant(w, r, client)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		s.handleTokenExchange(w, r, client)
	default:
		log.Printf("[OAUTH_FLOW] ✗ Unsupported grant type: %s", grantType)
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type not supported")
	}
}

func (s *authorizationServer) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unable to parse form")
		return
	}
	client, err := s.authenticateClient(r, "")
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	token := strings.TrimSpace(r.PostFormValue("token"))
	if token == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token required")
		return
	}
	tokenTypeHint := strings.TrimSpace(r.PostFormValue("token_type_hint"))
	if tokenTypeHint == "" || tokenTypeHint == "refresh_token" {
		if rt, ok := s.store.GetRefreshToken(token); ok && rt.ClientID == client.ID {
			active := time.Now().Before(rt.ExpiresAt) && rt.ConsumedAt.IsZero()
			writeJSON(w, http.StatusOK, map[string]any{
				"active":     active,
				"sub":        rt.HumanID,
				"client_id":  rt.ClientID,
				"scope":      rt.Scope,
				"exp":        rt.ExpiresAt.Unix(),
				"iat":        rt.IssuedAt.Unix(),
				"token_type": "refresh_token",
			})
			return
		}
		if tokenTypeHint == "refresh_token" {
			writeJSON(w, http.StatusOK, map[string]any{"active": false})
			return
		}
	}

	claims, err := s.verifyAccessToken(token)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	clientID, _ := claims["client_id"].(string)
	exp, _ := claims["exp"]
	iat, _ := claims["iat"]
	aud := claims["aud"]
	iss := claims["iss"]
	writeJSON(w, http.StatusOK, map[string]any{
		"active":     true,
		"sub":        sub,
		"client_id":  clientID,
		"scope":      scope,
		"exp":        exp,
		"iat":        iat,
		"aud":        aud,
		"iss":        iss,
		"token_type": "access_token",
	})
}

func (s *authorizationServer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unable to parse form")
		return
	}
	if _, err := s.authenticateClient(r, ""); err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	token := strings.TrimSpace(r.PostFormValue("token"))
	if token == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token required")
		return
	}
	tokenTypeHint := strings.TrimSpace(r.PostFormValue("token_type_hint"))
	if tokenTypeHint == "" || tokenTypeHint == "refresh_token" {
		s.store.RevokeRefreshTokenFamily(token)
	}
	w.WriteHeader(http.StatusOK)
}

func (s *authorizationServer) handleSubjectAssertion(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req struct {
		HumanID    string `json:"human_id"`
		Email      string `json:"email"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
		return
	}

	human, err := s.resolveHumanSelection(r.Context(), req.HumanID, req.Email)
	if err != nil {
		status := http.StatusBadRequest
		description := err.Error()
		if errors.Is(err, errHumanSelectionRequired) {
			description = "human_id or email is required"
		}
		if errors.Is(err, identity.ErrHumanNotFound) {
			description = "requested human not found"
		}
		writeOAuthError(w, status, "invalid_request", description)
		return
	}

	var ttl time.Duration
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	token, expiresIn, err := s.signer.IssueSubjectAssertion(r.Context(), human.ID, ttl)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"assertion":   token,
		"expires_in":  expiresIn,
		"human_id":    human.ID,
		"human_email": human.Email,
	})
}

func (s *authorizationServer) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client store.Client) {
	log.Printf("[TOKEN] Processing authorization code grant: client_id=%s", client.ID)

	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	if code == "" {
		log.Printf("[VALIDATE] ✗ Authorization code missing")
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code required")
		return
	}

	codePrefix := code
	if len(code) > 10 {
		codePrefix = code[:10] + "..."
	}
	log.Printf("[VALIDATE] Verifying authorization code: %s", codePrefix)

	record, err := s.store.ConsumeCode(code)
	if err != nil {
		log.Printf("[VALIDATE] ✗ Invalid or already consumed code")
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid code")
		return
	}

	if record.ClientID != client.ID {
		log.Printf("[VALIDATE] ✗ Code not issued to this client: code_client=%s, request_client=%s", record.ClientID, client.ID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code not issued to client")
		return
	}

	if time.Now().After(record.ExpiresAt) {
		log.Printf("[VALIDATE] ✗ Authorization code expired: expired_at=%v", record.ExpiresAt)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code expired")
		return
	}

	if redirectURI != "" && redirectURI != record.RedirectURI {
		log.Printf("[VALIDATE] ✗ Redirect URI mismatch: expected=%s, got=%s", record.RedirectURI, redirectURI)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	log.Printf("[VALIDATE] ✓ Code valid: client_match=true, not_expired=true, redirect_uri_match=true")

	if record.CodeChallenge != "" {
		codeVerifier := strings.TrimSpace(r.PostFormValue("code_verifier"))
		log.Printf("[VALIDATE] Verifying PKCE: method=%s", record.CodeChallengeMethod)

		if !validCodeVerifier(codeVerifier) {
			log.Printf("[VALIDATE] ✗ Invalid code_verifier format")
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid code_verifier")
			return
		}

		if !verifyPKCE(record.CodeChallengeMethod, record.CodeChallenge, codeVerifier) {
			log.Printf("[VALIDATE] ✗ PKCE verification failed")
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier mismatch")
			return
		}
		log.Printf("[VALIDATE] ✓ PKCE verified successfully")
	} else if client.Type == store.ClientTypePublic {
		log.Printf("[VALIDATE] ✗ PKCE required for public clients but not provided")
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code_verifier required for public clients")
		return
	}

	if !scopeSubsetList(record.Scope, client.Scopes) {
		log.Printf("[VALIDATE] ✗ Scope not allowed: requested=%s, allowed=%v", record.Scope, client.Scopes)
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed")
		return
	}
	log.Printf("[VALIDATE] ✓ Scope validated: %s", record.Scope)

	log.Printf("[VALIDATE] Looking up human: human_id=%s", record.HumanID)
	human, err := s.lookupHumanByID(r.Context(), record.HumanID)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, identity.ErrHumanNotFound) {
			log.Printf("[VALIDATE] ✗ Human not found: %s", record.HumanID)
			if !s.allowLegacy {
				writeOAuthError(w, status, "invalid_grant", "human not registered")
				return
			}
		} else {
			log.Printf("[VALIDATE] ✗ Error looking up human: %v", err)
			status = http.StatusInternalServerError
		}
		writeOAuthError(w, status, "invalid_grant", err.Error())
		return
	}
	log.Printf("[VALIDATE] ✓ Human found: %s (%s)", human.ID, human.Email)

	log.Printf("[TOKEN] Issuing tokens: subject=%s, scope=%s", human.ID, record.Scope)
	access, expiresIn, err := s.signer.IssueAccessWithClaims(r.Context(), human.ID, client.ID, record.Scope, s.humanExtraClaims(human))
	if err != nil {
		log.Printf("[TOKEN] ✗ Token issuance failed: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	refresh := random.NewID()
	familyID := random.NewID()
	log.Printf("[TOKEN] Generating refresh token: family_id=%s", familyID)
	s.store.SaveRefreshToken(store.RefreshToken{
		Token:     refresh,
		ClientID:  client.ID,
		HumanID:   human.ID,
		Scope:     record.Scope,
		FamilyID:  familyID,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: time.Now().Add(s.cfg.RefreshTokenTTL),
	})

	log.Printf("[TOKEN] ✓ Tokens issued: subject=%s, expires_in=%d, refresh_token=true", human.ID, expiresIn)

	writeTokenResponse(w, map[string]any{
		"access_token":  access,
		"token_type":    "bearer",
		"expires_in":    expiresIn,
		"refresh_token": refresh,
		"scope":         record.Scope,
	})
}

func (s *authorizationServer) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client store.Client) {
	log.Printf("[TOKEN] Processing refresh token grant: client_id=%s", client.ID)

	token := r.PostFormValue("refresh_token")
	if token == "" {
		log.Printf("[VALIDATE] ✗ Refresh token missing")
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token required")
		return
	}

	tokenPrefix := token
	if len(token) > 10 {
		tokenPrefix = token[:10] + "..."
	}
	log.Printf("[VALIDATE] Looking up refresh token: %s", tokenPrefix)

	rt, ok := s.store.GetRefreshToken(token)
	if !ok || rt.ClientID != client.ID {
		log.Printf("[VALIDATE] ✗ Unknown or mismatched refresh token: found=%v, client_match=%v", ok, ok && rt.ClientID == client.ID)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}
	log.Printf("[VALIDATE] ✓ Refresh token found: family_id=%s", rt.FamilyID)

	if !rt.ConsumedAt.IsZero() {
		log.Printf("[VALIDATE] ✗ Refresh token reuse detected! Revoking entire family: family_id=%s", rt.FamilyID)
		s.store.RevokeRefreshTokenFamily(token)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected")
		return
	}
	log.Printf("[VALIDATE] ✓ No token reuse detected")

	if !scopeSubsetList(rt.Scope, client.Scopes) {
		log.Printf("[VALIDATE] ✗ Scope not allowed: token_scope=%s, allowed=%v", rt.Scope, client.Scopes)
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed")
		return
	}

	if time.Now().After(rt.ExpiresAt) {
		log.Printf("[VALIDATE] ✗ Refresh token expired: expires_at=%v", rt.ExpiresAt)
		s.store.RevokeRefreshTokenFamily(token)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	log.Printf("[VALIDATE] ✓ Refresh token valid: expires_at=%v", rt.ExpiresAt)

	human, err := s.lookupHumanByID(r.Context(), rt.HumanID)
	if err != nil {
		status := http.StatusBadRequest
		if !errors.Is(err, identity.ErrHumanNotFound) {
			status = http.StatusInternalServerError
		}
		log.Printf("[VALIDATE] ✗ Human lookup failed: %v", err)
		writeOAuthError(w, status, "invalid_grant", err.Error())
		return
	}

	log.Printf("[TOKEN] Rotating refresh token: old_family_id=%s", rt.FamilyID)
	access, expiresIn, err := s.signer.IssueAccessWithClaims(r.Context(), human.ID, client.ID, rt.Scope, s.humanExtraClaims(human))
	if err != nil {
		log.Printf("[TOKEN] ✗ Token issuance failed: %v", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	newRefresh := random.NewID()
	next := store.RefreshToken{
		Token:     newRefresh,
		ClientID:  rt.ClientID,
		HumanID:   rt.HumanID,
		Scope:     rt.Scope,
		FamilyID:  rt.FamilyID,
		IssuedAt:  time.Now().UTC(),
		ExpiresAt: rt.ExpiresAt,
	}

	log.Printf("[TOKEN] Rotating to new refresh token in family: %s", rt.FamilyID)
	if _, err := s.store.RotateRefreshToken(token, next); err != nil {
		if errors.Is(err, store.ErrRefreshTokenConsumed) || errors.Is(err, store.ErrRefreshTokenFamilyReset) {
			log.Printf("[TOKEN] ✗ Rotation failed - token was consumed concurrently: %v", err)
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token reuse detected")
			return
		}
		log.Printf("[TOKEN] ✗ Rotation failed: %v", err)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}

	log.Printf("[TOKEN] ✓ Refresh token rotated successfully: subject=%s, family_id=%s", human.ID, rt.FamilyID)

	writeTokenResponse(w, map[string]any{
		"access_token":  access,
		"token_type":    "bearer",
		"expires_in":    expiresIn,
		"refresh_token": newRefresh,
		"scope":         rt.Scope,
	})
}

func (s *authorizationServer) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, client store.Client) {
	log.Printf("[TOKEN] Processing client credentials grant: client_id=%s", client.ID)

	scope := r.PostFormValue("scope")
	if scope == "" {
		scope = strings.Join(client.Scopes, " ")
		log.Printf("[VALIDATE] No scope requested, using client default scopes: %s", scope)
	} else {
		log.Printf("[VALIDATE] Requested scope: %s", scope)
	}

	if !scopeSubsetList(scope, client.Scopes) {
		log.Printf("[VALIDATE] ✗ Requested scope not allowed: requested=%s, allowed=%v", scope, client.Scopes)
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed")
		return
	}
	log.Printf("[VALIDATE] ✓ Scope validated: %s", scope)

	subject := "client:" + client.ID

	// RFC 9449: Check for DPoP header
	dpopHeader := r.Header.Get("DPoP")
	var access string
	var expiresIn int
	var err error
	var tokenType string

	if dpopHeader != "" {
		// Validate DPoP proof for token request
		log.Printf("[DPoP] DPoP header detected, validating proof...")
		tokenEndpointURL := s.cfg.Issuer + "/token"
		jkt, dpopErr := auth.ValidateDPoPForTokenRequest(dpopHeader, r.Method, tokenEndpointURL, s.jtiStore)
		if dpopErr != nil {
			log.Printf("[DPoP] ✗ DPoP validation failed: %v", dpopErr)
			writeOAuthError(w, http.StatusBadRequest, "invalid_dpop_proof", dpopErr.Error())
			return
		}

		log.Printf("[DPoP] ✓ DPoP proof validated, binding token to jkt=%s...", jkt[:16]+"...")

		// Issue DPoP-bound access token
		access, expiresIn, err = s.signer.IssueAccessWithDPoP(r.Context(), subject, client.ID, scope, jkt, nil)
		if err != nil {
			log.Printf("[TOKEN] ✗ DPoP token issuance failed: %v", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}

		tokenType = "DPoP"
		log.Printf("[TOKEN] ✓ DPoP-bound token issued: subject=%s, expires_in=%d", subject, expiresIn)
	} else {
		// Standard Bearer token
		log.Printf("[TOKEN] Issuing standard bearer token: subject=%s, scope=%s", subject, scope)
		access, expiresIn, err = s.signer.IssueAccess(r.Context(), subject, client.ID, scope)
		if err != nil {
			log.Printf("[TOKEN] ✗ Token issuance failed: %v", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}

		tokenType = "Bearer"
		log.Printf("[TOKEN] ✓ Client credentials token issued: subject=%s, expires_in=%d", subject, expiresIn)
	}

	writeTokenResponse(w, map[string]any{
		"access_token": access,
		"token_type":   tokenType,
		"expires_in":   expiresIn,
		"scope":        scope,
	})
}

func (s *authorizationServer) handleTokenExchange(w http.ResponseWriter, r *http.Request, client store.Client) {
	subjectToken := r.PostFormValue("subject_token")
	subjectTokenType := r.PostFormValue("subject_token_type")
	actorToken := r.PostFormValue("actor_token")
	actorTokenType := r.PostFormValue("actor_token_type")
	audience := strings.TrimSpace(r.PostFormValue("audience"))
	if audience == "" {
		audience = strings.TrimSpace(r.PostFormValue("resource"))
	}
	if audience == "" {
		audience = s.cfg.Audience
	}
	if strings.EqualFold(audience, s.cfg.Issuer) {
		// Prevent misconfiguration where the token exchange audience is the issuer
		// (e.g. http://as:8080). Default back to the configured API audience so that
		// OBO tokens target the resource server as expected.
		audience = s.cfg.Audience
	}
	if len(client.Audiences) > 0 && !stringInList(client.Audiences, audience) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_target", "audience not allowed")
		return
	}

	enableRAR := s.cfg.EnableRAR
	log.Printf("[TOKEN_EXCHANGE] Starting token exchange: enable_rar=%v, client_id=%s", enableRAR, client.ID)
	var rar []obo.RAR
	var err error

	if enableRAR {
		// RAR mode: parse authorization_details with scope fallback
		rarRaw := r.PostFormValue("authorization_details")
		rar, err = obo.ParseRAR(rarRaw)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		// Fallback: convert scope to RAR if no authorization_details
		if len(rar) == 0 {
			scope := r.PostFormValue("scope")
			if scope != "" {
				actions := strings.Fields(scope)
				if len(actions) > 0 {
					rar = []obo.RAR{{
						Type:    "scope",
						Actions: actions,
					}}
				}
			}
		}
	} else {
		// Scope-only mode: reject authorization_details, require scope
		if r.PostFormValue("authorization_details") != "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request",
				"authorization_details not supported (ENABLE_RAR=false)")
			return
		}
		scope := r.PostFormValue("scope")
		if scope == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request",
				"scope required when RAR disabled")
			return
		}
		// Convert scope to internal format for processing
		actions := strings.Fields(scope)
		if len(actions) > 0 {
			rar = []obo.RAR{{
				Type:    "scope",
				Actions: actions,
			}}
		}
	}
	log.Printf("[TOKEN_EXCHANGE] RAR after parsing: %+v", rar)

	subject, subjectClaims, err := s.oboService.ValidateSubjectToken(r.Context(), subjectToken, subjectTokenType)
	if err != nil {
		code := "invalid_request"
		if errors.Is(err, obo.ErrInvalidToken) {
			code = "invalid_grant"
		}
		writeOAuthError(w, http.StatusBadRequest, code, err.Error())
		return
	}

	// Standard OAuth 2.0: Validate requested scopes/actions against BOTH client and subject scopes
	// Extract all requested actions from RAR (which may have come from scope parameter or authorization_details)
	requestedActions := extractActionsFromRAR(rar)
	log.Printf("[TOKEN_EXCHANGE] Validating scopes: requested_actions=%v, client_scopes=%v", requestedActions, client.Scopes)
	if len(requestedActions) > 0 {
		// Step 1: Check client-level scope restrictions (what the client is allowed to request)
		if !scopeSubsetList(strings.Join(requestedActions, " "), client.Scopes) {
			log.Printf("[TOKEN_EXCHANGE] ✗ Scope validation failed: requested %v not subset of client scopes %v", requestedActions, client.Scopes)
			writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed for this client")
			return
		}
		// Step 2: Check subject-level scopes (what the human has granted)
		if !scopeSubset(strings.Join(requestedActions, " "), subjectClaims["scope"]) {
			log.Printf("[TOKEN_EXCHANGE] ✗ Scope validation failed: requested %v exceeds subject scopes", requestedActions)
			writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope exceeds subject token scope")
			return
		}
		log.Printf("[TOKEN_EXCHANGE] ✓ Scope validation passed")
	}
	human, err := s.lookupHumanByID(r.Context(), subject)
	if err != nil {
		status := http.StatusBadRequest
		if !errors.Is(err, identity.ErrHumanNotFound) {
			status = http.StatusInternalServerError
		}
		writeOAuthError(w, status, "invalid_request", err.Error())
		return
	}

	actClaim, err := s.oboService.ResolveAgent(r.Context(), actorToken, actorTokenType, client.ID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	agentIDParam := r.PostFormValue("agent_id")
	agent, err := s.resolveAgent(r.Context(), client.ID, agentIDParam, actClaim)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, identity.ErrAgentNotFound):
			status = http.StatusBadRequest
		case errors.Is(err, errAgentAmbiguous):
			status = http.StatusBadRequest
		case errors.Is(err, errAgentClientMismatch):
			status = http.StatusBadRequest
		default:
			if !errors.Is(err, identity.ErrAgentNotFound) {
				status = http.StatusInternalServerError
			}
		}
		writeOAuthError(w, status, "invalid_request", err.Error())
		return
	}

	// Standard OAuth 2.0 Token Exchange (RFC 8693) behavior:
	// The agent can only access what BOTH the client is allowed to request AND
	// what the human has been granted. Compute the intersection of client and subject scopes.
	// Extract subject's authorized scopes
	subjectScope := ""
	if scopeClaim, ok := subjectClaims["scope"].(string); ok {
		subjectScope = scopeClaim
	}
	subjectScopes := strings.Fields(subjectScope)

	// Compute intersection: client.Scopes ∩ subject.scopes ∩ agent.Capabilities.
	// This is the maximum set of scopes the agent can be granted. The agent's own
	// capabilities are part of the intersection: without them any agent
	// registered to a client could exercise that client's entire scope set,
	// ignoring the per-agent restrictions capabilities exist to express.
	// An agent registered with no capabilities is therefore granted nothing.
	allowedScopes := intersectScopes(client.Scopes, subjectScopes)
	allowedScopes = intersectScopes(allowedScopes, agent.Capabilities)

	// Pass the allowed scope intersection to ComputePerms
	// ComputePerms will further filter based on requested scopes/actions
	perms, filteredRAR, hash, err := s.oboService.ComputePerms(human.ID, rar, allowedScopes)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, obo.ErrNoPermissions) {
			status = http.StatusForbidden
		}
		writeOAuthError(w, status, "invalid_request", err.Error())
		return
	}

	claims := obo.OBOClaims{
		Iss:                   s.cfg.Issuer,
		Aud:                   audience,
		Sub:                   human.ID,
		Act:                   obo.ActClaim{Actor: agent.ID, ClientID: agent.ClientID, InstanceID: actClaim.InstanceID},
		Perm:                  perms,
		HumanEntitlementsHash: hash,
	}

	// Only include RAR in token if enabled
	if enableRAR {
		claims.AuthorizationDetails = filteredRAR
	}

	token, expiresIn, err := s.oboService.IssueOBOToken(r.Context(), claims)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	response := map[string]any{
		"access_token":      token,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        "bearer",
		"expires_in":        expiresIn,
		"human_subject":     subject,
		"actor":             actClaim.Actor,
		"perm":              perms,
	}

	// Only include authorization_details in response if enabled
	if enableRAR {
		response["authorization_details"] = rar
	}

	writeTokenResponse(w, response)
}

func (s *authorizationServer) authenticateClient(r *http.Request, grantType string) (store.Client, error) {
	// RFC 7523: Check for JWT Bearer Client Assertion authentication
	assertionType := r.PostFormValue("client_assertion_type")
	assertion := r.PostFormValue("client_assertion")

	if assertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" && assertion != "" {
		return s.authenticateClientWithAssertion(r, assertion, grantType)
	}

	// Standard client_secret authentication (existing flow)
	header := r.Header.Get("Authorization")
	var clientID, clientSecret string
	if header != "" && strings.HasPrefix(strings.ToLower(header), "basic ") {
		raw := strings.TrimSpace(header[6:])
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return store.Client{}, errors.New("invalid basic auth")
		}
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			return store.Client{}, errors.New("invalid basic auth")
		}
		clientID = parts[0]
		clientSecret = parts[1]
	} else {
		clientID = r.PostFormValue("client_id")
		clientSecret = r.PostFormValue("client_secret")
	}
	if clientID == "" {
		return store.Client{}, errors.New("client_id required")
	}
	client, ok, err := s.clients.GetClient(r.Context(), clientID)
	if err != nil {
		return store.Client{}, errors.New("client lookup failed")
	}
	if !ok {
		return store.Client{}, errors.New("unknown client")
	}
	normalizedGrant := store.NormalizeGrantType(grantType)
	if normalizedGrant != "" && !clientAllowsGrant(client, normalizedGrant) {
		return store.Client{}, errors.New("unauthorized client")
	}
	if client.Type == store.ClientTypeConfidential {
		if clientSecret == "" || client.Secret != clientSecret {
			return store.Client{}, errors.New("invalid client secret")
		}
	}
	return client, nil
}

// authenticateClientWithAssertion implements RFC 7523 JWT Bearer Client Assertion authentication.
func (s *authorizationServer) authenticateClientWithAssertion(r *http.Request, assertion string, grantType string) (store.Client, error) {
	// Build the expected audience (token endpoint URL)
	expectedAudience := s.cfg.Issuer + "/token"

	// Parse JWT to extract client_id from iss/sub claims (unauthenticated parse)
	// We need this to look up the client's public key
	type tempClaims struct {
		Issuer string `json:"iss"`
		jwt.RegisteredClaims
	}
	parser := jwt.NewParser()
	token, _, err := parser.ParseUnverified(assertion, &tempClaims{})
	if err != nil {
		log.Printf("[RFC 7523] Failed to parse assertion: %v", err)
		return store.Client{}, errors.New("invalid assertion format")
	}

	claims, ok := token.Claims.(*tempClaims)
	if !ok || claims.Issuer == "" {
		return store.Client{}, errors.New("assertion missing issuer")
	}

	clientID := claims.Issuer

	// Look up client by client_id
	client, ok, err := s.clients.GetClient(r.Context(), clientID)
	if err != nil {
		log.Printf("[RFC 7523] Client lookup failed for %s: %v", clientID, err)
		return store.Client{}, errors.New("client lookup failed")
	}
	if !ok {
		log.Printf("[RFC 7523] Unknown client: %s", clientID)
		return store.Client{}, errors.New("unknown client")
	}

	// Verify client has public key registered
	if client.PublicKey == "" {
		log.Printf("[RFC 7523] Client %s has no public key registered", clientID)
		return store.Client{}, errors.New("client not configured for JWT assertion authentication")
	}

	// Validate JWT assertion using client's public key
	if err := auth.ValidateJWTAssertion(assertion, client, expectedAudience, s.jtiStore); err != nil {
		log.Printf("[RFC 7523] Assertion validation failed for %s: %v", clientID, err)
		return store.Client{}, fmt.Errorf("assertion validation failed: %w", err)
	}

	// Check client is authorized for requested grant type
	normalizedGrant := store.NormalizeGrantType(grantType)
	if normalizedGrant != "" && !clientAllowsGrant(client, normalizedGrant) {
		log.Printf("[RFC 7523] Client %s not authorized for grant type %s", clientID, normalizedGrant)
		return store.Client{}, errors.New("unauthorized client")
	}

	log.Printf("[RFC 7523] ✓ Client %s authenticated via JWT assertion", clientID)
	return client, nil
}

func writeTokenResponse(w http.ResponseWriter, payload map[string]any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, payload)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write json: %v", err)
	}
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]any{
		"error":             code,
		"error_description": description,
	})
}

func rateLimitMiddleware(limiter *ratelimit.Limiter, next http.Handler) http.Handler {
	if limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiter.Allow(clientIP(r)) {
			writeOAuthError(w, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
}

func validCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for _, r := range verifier {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' || r == '_' || r == '~' {
			continue
		}
		return false
	}
	return true
}

func verifyPKCE(method, challenge, verifier string) bool {
	if method != "S256" {
		return false
	}
	digest := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(digest[:])
	return subtleConstantTimeCompare(expected, challenge)
}

func subtleConstantTimeCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func methodHandler(method string, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		fn(w, r)
	}
}

func methodNotAllowed(w http.ResponseWriter, r *http.Request, allowed ...string) {
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
}

func loadDotEnv() {
	file := ".env"
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
}

func logConfiguration(cfg *config.Config) {
	log.Printf("config: issuer=%s audience=%s allow_legacy=%t admin_token_set=%t seed=%s client_store=%s clients_db=%s admin_addr=%s code_ttl=%s access_ttl=%s refresh_ttl=%s obo_ttl=%s signing_key_dir=%s key_rotation_interval=%s authorize_rl=%d/%d token_rl=%d/%d introspect_rl=%d/%d admin_rl=%d/%d", cfg.Issuer, cfg.Audience, cfg.AllowLegacy, cfg.AdminToken != "", cfg.SeedIdentitiesPath, cfg.ClientStoreDriver, cfg.ClientDBPath, cfg.AdminAddr, cfg.CodeTTL, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.OBOTokenTTL, cfg.SigningKeyDir, cfg.SigningKeyRotationInterval, cfg.AuthorizeRateLimitRPS, cfg.AuthorizeRateLimitBurst, cfg.TokenRateLimitRPS, cfg.TokenRateLimitBurst, cfg.IntrospectRateLimitRPS, cfg.IntrospectRateLimitBurst, cfg.AdminRateLimitRPS, cfg.AdminRateLimitBurst)
}

func buildClientStore(cfg *config.Config) (store.ClientStore, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.ClientStoreDriver)) {
	case "memory", "mem", "in-memory":
		return memstore.NewClientStore(), nil
	case "sqlite", "":
		if _, err := exec.LookPath("sqlite3"); err != nil {
			return nil, fmt.Errorf("sqlite3 not found: %w", err)
		}
		if err := ensureDir(filepath.Dir(cfg.ClientDBPath)); err != nil {
			return nil, err
		}
		return sqlstore.NewClientStore(cfg.ClientDBPath)
	default:
		return nil, fmt.Errorf("unsupported client store driver %q", cfg.ClientStoreDriver)
	}
}

func ensureDir(path string) error {
	if path == "." || path == "" {
		return nil
	}
	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}
	return nil
}

func clientAllowsGrant(client store.Client, grantType string) bool {
	normalizedRequested := store.NormalizeGrantType(strings.TrimSpace(grantType))
	for _, grant := range client.GrantTypes {
		normalizedAllowed := store.NormalizeGrantType(strings.TrimSpace(grant))
		if grant == grantType || normalizedAllowed == normalizedRequested {
			return true
		}
	}
	return false
}

func redirectURIMatch(allowed []string, requested string) bool {
	for _, uri := range allowed {
		if uri == requested {
			return true
		}
	}
	return false
}

// extractActionsFromRAR extracts all actions from RAR entries into a flat list
func extractActionsFromRAR(rar []obo.RAR) []string {
	if len(rar) == 0 {
		return nil
	}
	var actions []string
	for _, entry := range rar {
		actions = append(actions, entry.Actions...)
	}
	return actions
}

func scopeSubsetList(requested string, allowed []string) bool {
	req := strings.Fields(strings.TrimSpace(requested))
	if len(req) == 0 {
		return true
	}
	if len(allowed) == 0 {
		return false
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = struct{}{}
	}
	for _, scope := range req {
		if _, ok := allowedSet[scope]; !ok {
			return false
		}
	}
	return true
}

// intersectScopes returns the intersection of two scope lists
// Used to compute: client.Scopes ∩ subject.scopes
func intersectScopes(clientScopes []string, subjectScopes []string) []string {
	if len(clientScopes) == 0 || len(subjectScopes) == 0 {
		return []string{}
	}

	subjectSet := make(map[string]struct{}, len(subjectScopes))
	for _, scope := range subjectScopes {
		subjectSet[scope] = struct{}{}
	}

	intersection := []string{}
	for _, scope := range clientScopes {
		if _, ok := subjectSet[scope]; ok {
			intersection = append(intersection, scope)
		}
	}

	return intersection
}

func stringInList(list []string, value string) bool {
	for _, entry := range list {
		if entry == value {
			return true
		}
	}
	return false
}

func scopeSubset(requested string, subjectScope any) bool {
	req := strings.Fields(strings.TrimSpace(requested))
	if len(req) == 0 {
		return true
	}
	var subject []string
	switch v := subjectScope.(type) {
	case string:
		subject = strings.Fields(strings.TrimSpace(v))
	case []string:
		subject = v
	case []any:
		for _, entry := range v {
			if s, ok := entry.(string); ok {
				subject = append(subject, s)
			}
		}
	}
	if len(subject) == 0 {
		return false
	}
	allowed := map[string]struct{}{}
	for _, s := range subject {
		allowed[s] = struct{}{}
	}
	for _, s := range req {
		if _, ok := allowed[s]; !ok {
			return false
		}
	}
	return true
}

func (s *authorizationServer) verifyAccessToken(token string) (internaljwt.MapClaims, error) {
	claims, err := s.signer.Verify(token, s.cfg.Audience)
	if err == nil {
		return claims, nil
	}
	if s.cfg.Issuer != "" && s.cfg.Issuer != s.cfg.Audience {
		return s.signer.Verify(token, s.cfg.Issuer)
	}
	return nil, err
}

func buildSigner(cfg *config.Config) (*internaljwt.Signer, error) {
	var (
		keySet *internaljwt.KeySet
		err    error
	)
	if cfg.SigningKeyDir != "" {
		keySet, err = internaljwt.LoadKeySetFromDir(cfg.SigningKeyDir, cfg.SigningKeyID)
	} else {
		keySet, err = internaljwt.LoadKeySetFromPEM(cfg.SigningKeyPEM, cfg.SigningKeyID)
	}
	if err != nil {
		return nil, err
	}
	return internaljwt.NewSignerWithKeySet(cfg.Issuer, cfg.Audience, keySet, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.OBOTokenTTL)
}

func startKeyRotation(cfg *config.Config, signer *internaljwt.Signer) {
	interval := cfg.SigningKeyRotationInterval
	if interval <= 0 || cfg.SigningKeyDir == "" {
		return
	}
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			keySet, err := internaljwt.LoadKeySetFromDir(cfg.SigningKeyDir, cfg.SigningKeyID)
			if err != nil {
				log.Printf("key rotation reload failed: %v", err)
				continue
			}
			if err := signer.UpdateKeys(keySet); err != nil {
				log.Printf("key rotation update failed: %v", err)
				continue
			}
			log.Printf("key rotation: reloaded %d keys (active kid=%s)", len(keySet.PrivateKeys), keySet.ActiveKeyID)
		}
	}()
}

func seedIdentities(ctx context.Context, store identity.Store, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read seed file: %w", err)
	}
	var doc struct {
		Humans []struct {
			ID         string            `json:"id"`
			Email      string            `json:"email"`
			Name       string            `json:"name"`
			TenantID   string            `json:"tenant_id"`
			Password   string            `json:"password"`
			Attributes map[string]string `json:"attributes"`
		} `json:"humans"`
		Agents []struct {
			ID            string            `json:"id"`
			AgentID       string            `json:"agent_id"`
			Name          string            `json:"name"`
			ClientID      string            `json:"client_id"`
			Capabilities  []string          `json:"capabilities"`
			DPoPPublicJWK string            `json:"dpop_public_jwk"`
			PolicyID      string            `json:"policy_id"`
			TenantID      string            `json:"tenant_id"`
			Metadata      map[string]string `json:"metadata"`
		} `json:"agents"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse seed file: %w", err)
	}
	for _, raw := range doc.Humans {
		input, err := identity.ValidateHuman(identity.HumanInput{
			Email:      raw.Email,
			Name:       raw.Name,
			TenantID:   raw.TenantID,
			Attributes: raw.Attributes,
		})
		if err != nil {
			log.Printf("seed human skipped: %v", err)
			continue
		}
		human := identity.Human{
			ID:         strings.TrimSpace(raw.ID),
			Email:      input.Email,
			Name:       input.Name,
			TenantID:   input.TenantID,
			Attributes: input.Attributes,
		}
		// Without a password hash a seeded human can only sign in when DEV_MODE
		// is on, so seeds that carry one stay usable with dev mode off.
		if raw.Password != "" {
			hash, err := auth.HashPassword(raw.Password)
			if err != nil {
				return fmt.Errorf("seed human %s: hash password: %w", human.Email, err)
			}
			human.PasswordHash = hash
		}
		if _, err := store.CreateHuman(ctx, human); err != nil {
			if errors.Is(err, identity.ErrHumanEmailExists) {
				log.Printf("seed human skipped (exists): %s", human.Email)
				continue
			}
			return fmt.Errorf("seed human %s: %w", human.Email, err)
		}
		log.Printf("seeded human: %s (%s)", human.ID, human.Email)
	}
	for _, raw := range doc.Agents {
		input, err := identity.ValidateAgent(identity.AgentInput{
			AgentID:       raw.AgentID,
			Name:          raw.Name,
			ClientID:      raw.ClientID,
			Capabilities:  raw.Capabilities,
			DPoPPublicJWK: raw.DPoPPublicJWK,
			PolicyID:      raw.PolicyID,
			TenantID:      raw.TenantID,
			Metadata:      raw.Metadata,
		})
		if err != nil {
			log.Printf("seed agent skipped: %v", err)
			continue
		}
		agent := identity.Agent{
			ID:            strings.TrimSpace(raw.ID),
			AgentID:       input.AgentID,
			Name:          input.Name,
			ClientID:      input.ClientID,
			Capabilities:  input.Capabilities,
			DPoPPublicJWK: input.DPoPPublicJWK,
			PolicyID:      input.PolicyID,
			TenantID:      input.TenantID,
			Metadata:      input.Metadata,
		}
		if _, err := store.CreateAgent(ctx, agent); err != nil {
			if errors.Is(err, identity.ErrAgentLabelExists) {
				log.Printf("seed agent skipped (label exists): %s", agent.AgentID)
				continue
			}
			return fmt.Errorf("seed agent %s: %w", agent.Name, err)
		}
		log.Printf("seeded agent: %s (%s)", agent.ID, agent.Name)
	}
	return nil
}
