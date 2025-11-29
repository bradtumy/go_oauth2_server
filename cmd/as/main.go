package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"go_oauth2_server/internal/config"
	"go_oauth2_server/internal/httputil"
	"go_oauth2_server/internal/identity"
	internaljwt "go_oauth2_server/internal/jwt"
	"go_oauth2_server/internal/middleware"
	"go_oauth2_server/internal/obo"
	"go_oauth2_server/internal/random"
	"go_oauth2_server/internal/router"
	"go_oauth2_server/internal/store"
	memstore "go_oauth2_server/internal/store/mem"
)

func main() {
	config.LoadDotEnv()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	defaultClient := store.Client{
		ID:           cfg.DefaultClientID,
		Secret:       cfg.DefaultClientSecret,
		RedirectURI:  "http://localhost:8081/callback",
		Audience:     cfg.Audience,
		DefaultScope: "orders:export",
	}
	config.LogConfiguration(cfg)

	st := store.New(defaultClient)

	identityStore := memstore.New()
	if cfg.SeedIdentitiesPath != "" {
		if err := config.SeedIdentities(context.Background(), identityStore, cfg.SeedIdentitiesPath); err != nil {
			log.Fatalf("seed identities: %v", err)
		}
	}

	signer := internaljwt.NewSigner(cfg.Issuer, cfg.Audience, cfg.SigningKey, cfg.SigningKeyID, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.OBOTokenTTL)
	oboService := &obo.Service{Signer: signer, Issuer: cfg.Issuer, Audience: cfg.Audience, OBOTTL: cfg.OBOTokenTTL}

	srv := &authorizationServer{
		cfg:                cfg,
		store:              st,
		signer:             signer,
		oboService:         oboService,
		identities:         identityStore,
		allowLegacy:        cfg.AllowLegacy,
		legacyUsers:        map[string]string{"user:123": "demo-user"},
		legacyDefaultHuman: "user:123",
	}

	identityHandler := identity.NewHandler(identityStore, cfg.AdminToken)

	mux := router.SetupRoutes(srv, identityHandler)

	addr := ":8080"
	if v := os.Getenv("AS_LISTEN_ADDR"); v != "" {
		addr = v
	}

	log.Printf("Authorization server listening on %s", addr)
	if err := http.ListenAndServe(addr, middleware.Logging(mux)); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

type authorizationServer struct {
	cfg                *config.Config
	store              *store.Store
	signer             *internaljwt.Signer
	oboService         *obo.Service
	identities         identity.Store
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

func (s *authorizationServer) resolveAgent(ctx context.Context, clientID, requestedAgentID string, claim obo.ActClaim, actorProvided bool) (identity.Agent, error) {
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
		if actorProvided {
			return identity.Agent{}, identity.ErrAgentNotFound
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

func (s *authorizationServer) HandleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.signer.JWKS()
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	httputil.WriteJSON(w, http.StatusOK, jwks)
}

func (s *authorizationServer) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !strings.EqualFold(q.Get("response_type"), "code") {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only authorization_code supported")
		return
	}
	clientID := q.Get("client_id")
	client, ok := s.store.GetClient(clientID)
	if !ok {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "unauthorized_client", "unknown client")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = client.RedirectURI
	}
	if redirectURI == "" {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri required")
		return
	}
	human, err := s.resolveHumanSelection(r.Context(), q.Get("human_id"), q.Get("email"))
	if err != nil {
		status := http.StatusBadRequest
		description := err.Error()
		switch {
		case errors.Is(err, errHumanSelectionRequired):
			description = "human_id or email is required"
		case errors.Is(err, identity.ErrHumanNotFound):
			description = "requested human not found"
		default:
			status = http.StatusInternalServerError
		}
		httputil.WriteOAuthError(w, status, "invalid_request", description)
		return
	}
	scope := q.Get("scope")
	if scope == "" {
		scope = client.DefaultScope
	}

	code := random.NewID()
	state := q.Get("state")
	s.store.SaveCode(store.AuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		HumanID:     human.ID,
		RedirectURI: redirectURI,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(s.cfg.CodeTTL),
	})

	redirect, err := url.Parse(redirectURI)
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid redirect_uri")
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

func (s *authorizationServer) HandleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "unable to parse form")
		return
	}

	client, err := s.authenticateClient(r)
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}

	grantType := r.PostFormValue("grant_type")
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
		httputil.WriteOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type not supported")
	}
}

func (s *authorizationServer) HandleSubjectAssertion(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var req struct {
		HumanID    string `json:"human_id"`
		Email      string `json:"email"`
		TTLSeconds int    `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body")
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
		httputil.WriteOAuthError(w, status, "invalid_request", description)
		return
	}

	var ttl time.Duration
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	token, expiresIn, err := s.signer.IssueSubjectAssertion(r.Context(), human.ID, ttl)
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	httputil.WriteJSON(w, http.StatusOK, map[string]any{
		"assertion":   token,
		"expires_in":  expiresIn,
		"human_id":    human.ID,
		"human_email": human.Email,
	})
}

func (s *authorizationServer) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client store.Client) {
	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	if code == "" {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "code required")
		return
	}
	record, err := s.store.ConsumeCode(code)
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid code")
		return
	}
	if record.ClientID != client.ID {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "code not issued to client")
		return
	}
	if time.Now().After(record.ExpiresAt) {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "code expired")
		return
	}
	if redirectURI != "" && redirectURI != record.RedirectURI {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	human, err := s.lookupHumanByID(r.Context(), record.HumanID)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, identity.ErrHumanNotFound) {
			if !s.allowLegacy {
				httputil.WriteOAuthError(w, status, "invalid_grant", "human not registered")
				return
			}
		} else {
			status = http.StatusInternalServerError
		}
		httputil.WriteOAuthError(w, status, "invalid_grant", err.Error())
		return
	}
	access, expiresIn, err := s.signer.IssueAccessWithClaims(r.Context(), human.ID, client.ID, record.Scope, s.humanExtraClaims(human))
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	refresh := random.NewID()
	s.store.SaveRefreshToken(store.RefreshToken{
		Token:     refresh,
		ClientID:  client.ID,
		HumanID:   human.ID,
		Scope:     record.Scope,
		ExpiresAt: time.Now().Add(s.cfg.RefreshTokenTTL),
	})
	writeTokenResponse(w, map[string]any{
		"access_token":  access,
		"token_type":    "bearer",
		"expires_in":    expiresIn,
		"refresh_token": refresh,
		"scope":         record.Scope,
	})
}

func (s *authorizationServer) handleRefreshTokenGrant(w http.ResponseWriter, r *http.Request, client store.Client) {
	token := r.PostFormValue("refresh_token")
	if token == "" {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token required")
		return
	}
	rt, ok := s.store.GetRefreshToken(token)
	if !ok || rt.ClientID != client.ID {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		s.store.DeleteRefreshToken(token)
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	human, err := s.lookupHumanByID(r.Context(), rt.HumanID)
	if err != nil {
		status := http.StatusBadRequest
		if !errors.Is(err, identity.ErrHumanNotFound) {
			status = http.StatusInternalServerError
		}
		httputil.WriteOAuthError(w, status, "invalid_grant", err.Error())
		return
	}
	access, expiresIn, err := s.signer.IssueAccessWithClaims(r.Context(), human.ID, client.ID, rt.Scope, s.humanExtraClaims(human))
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeTokenResponse(w, map[string]any{
		"access_token": access,
		"token_type":   "bearer",
		"expires_in":   expiresIn,
		"scope":        rt.Scope,
	})
}

func (s *authorizationServer) handleClientCredentialsGrant(w http.ResponseWriter, r *http.Request, client store.Client) {
	scope := r.PostFormValue("scope")
	if scope == "" {
		scope = client.DefaultScope
	}
	subject := "client:" + client.ID
	access, expiresIn, err := s.signer.IssueAccess(r.Context(), subject, client.ID, scope)
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeTokenResponse(w, map[string]any{
		"access_token": access,
		"token_type":   "bearer",
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

	rarRaw := r.PostFormValue("authorization_details")
	rar, err := obo.ParseRAR(rarRaw)
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
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

	subject, _, err := s.oboService.ValidateSubjectToken(r.Context(), subjectToken, subjectTokenType)
	if err != nil {
		code := "invalid_request"
		if errors.Is(err, obo.ErrInvalidToken) {
			code = "invalid_grant"
		}
		httputil.WriteOAuthError(w, http.StatusBadRequest, code, err.Error())
		return
	}
	human, err := s.lookupHumanByID(r.Context(), subject)
	if err != nil {
		status := http.StatusBadRequest
		if !errors.Is(err, identity.ErrHumanNotFound) {
			status = http.StatusInternalServerError
		}
		httputil.WriteOAuthError(w, status, "invalid_request", err.Error())
		return
	}

	actClaim, err := s.oboService.ResolveAgent(r.Context(), actorToken, actorTokenType, client.ID)
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	agentIDParam := r.PostFormValue("agent_id")
	agent, err := s.resolveAgent(r.Context(), client.ID, agentIDParam, actClaim, actorToken != "")
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
		httputil.WriteOAuthError(w, status, "invalid_request", err.Error())
		return
	}

	perms, filteredRAR, hash, err := s.oboService.ComputePerms(human.ID, rar, agent.Capabilities)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, obo.ErrNoPermissions) {
			status = http.StatusForbidden
		}
		httputil.WriteOAuthError(w, status, "invalid_request", err.Error())
		return
	}

	claims := obo.OBOClaims{
		Iss:                   s.cfg.Issuer,
		Aud:                   audience,
		Sub:                   human.ID,
		Act:                   obo.ActClaim{Actor: agent.ID, ClientID: agent.ClientID, InstanceID: actClaim.InstanceID},
		AuthorizationDetails:  filteredRAR,
		Perm:                  perms,
		HumanEntitlementsHash: hash,
	}

	token, expiresIn, err := s.oboService.IssueOBOToken(r.Context(), claims)
	if err != nil {
		httputil.WriteOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}

	writeTokenResponse(w, map[string]any{
		"access_token":          token,
		"issued_token_type":     "urn:ietf:params:oauth:token-type:access_token",
		"token_type":            "bearer",
		"expires_in":            expiresIn,
		"human_subject":         subject,
		"actor":                 actClaim.Actor,
		"authorization_details": rar,
		"perm":                  perms,
	})
}

func (s *authorizationServer) authenticateClient(r *http.Request) (store.Client, error) {
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
	client, ok := s.store.GetClient(clientID)
	if !ok {
		return store.Client{}, errors.New("unknown client")
	}
	if client.Secret != "" && client.Secret != clientSecret {
		return store.Client{}, errors.New("invalid client secret")
	}
	return client, nil
}

func writeTokenResponse(w http.ResponseWriter, payload map[string]any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	httputil.WriteJSON(w, http.StatusOK, payload)
}


