package main

import (
	"bufio"
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
	internaljwt "go_oauth2_server/internal/jwt"
	"go_oauth2_server/internal/obo"
	"go_oauth2_server/internal/random"
	"go_oauth2_server/internal/store"
)

func main() {
	loadDotEnv()

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
	st := store.New(defaultClient)

	signer := internaljwt.NewSigner(cfg.Issuer, cfg.Audience, cfg.SigningKey, cfg.SigningKeyID, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.OBOTokenTTL)
	oboService := &obo.Service{Signer: signer, Issuer: cfg.Issuer, Audience: cfg.Audience, OBOTTL: cfg.OBOTokenTTL}

	srv := &authorizationServer{
		cfg:        cfg,
		store:      st,
		signer:     signer,
		oboService: oboService,
		users: map[string]string{
			"user:123": "demo-user",
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", methodHandler(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	}))
	mux.HandleFunc("/.well-known/jwks.json", methodHandler(http.MethodGet, srv.handleJWKS))
	mux.HandleFunc("/authorize", methodHandler(http.MethodGet, srv.handleAuthorize))
	mux.HandleFunc("/token", methodHandler(http.MethodPost, srv.handleToken))

	addr := ":8080"
	if v := os.Getenv("AS_LISTEN_ADDR"); v != "" {
		addr = v
	}

	log.Printf("Authorization server listening on %s", addr)
	if err := http.ListenAndServe(addr, loggingMiddleware(mux)); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

type authorizationServer struct {
	cfg        *config.Config
	store      *store.Store
	signer     *internaljwt.Signer
	oboService *obo.Service
	users      map[string]string
}

func (s *authorizationServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := s.signer.JWKS()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, jwks)
}

func (s *authorizationServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if !strings.EqualFold(q.Get("response_type"), "code") {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only authorization_code supported")
		return
	}
	clientID := q.Get("client_id")
	client, ok := s.store.GetClient(clientID)
	if !ok {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "unknown client")
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" {
		redirectURI = client.RedirectURI
	}
	if redirectURI == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri required")
		return
	}
	userID := r.Header.Get("X-Demo-User")
	if userID == "" {
		userID = "user:123"
	}
	if _, ok := s.users[userID]; !ok {
		writeOAuthError(w, http.StatusUnauthorized, "access_denied", "unknown user")
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
		UserID:      userID,
		RedirectURI: redirectURI,
		Scope:       scope,
		ExpiresAt:   time.Now().Add(s.cfg.CodeTTL),
	})

	redirect, err := url.Parse(redirectURI)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid redirect_uri")
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
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "unable to parse form")
		return
	}

	client, err := s.authenticateClient(r)
	if err != nil {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
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
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant type not supported")
	}
}

func (s *authorizationServer) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, client store.Client) {
	code := r.PostFormValue("code")
	redirectURI := r.PostFormValue("redirect_uri")
	if code == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code required")
		return
	}
	record, err := s.store.ConsumeCode(code)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid code")
		return
	}
	if record.ClientID != client.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code not issued to client")
		return
	}
	if time.Now().After(record.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code expired")
		return
	}
	if redirectURI != "" && redirectURI != record.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}
	access, expiresIn, err := s.signer.IssueAccess(r.Context(), record.UserID, client.ID, record.Scope)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	refresh := random.NewID()
	s.store.SaveRefreshToken(store.RefreshToken{
		Token:     refresh,
		ClientID:  client.ID,
		UserID:    record.UserID,
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
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "refresh_token required")
		return
	}
	rt, ok := s.store.GetRefreshToken(token)
	if !ok || rt.ClientID != client.ID {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "unknown refresh token")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		s.store.DeleteRefreshToken(token)
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token expired")
		return
	}
	access, expiresIn, err := s.signer.IssueAccess(r.Context(), rt.UserID, client.ID, rt.Scope)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
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
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
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
	audience := r.PostFormValue("audience")
	if audience == "" {
		audience = r.PostFormValue("resource")
	}
	if audience == "" {
		audience = s.cfg.Audience
	}

	rarRaw := r.PostFormValue("authorization_details")
	rar, err := obo.ParseRAR(rarRaw)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
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
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	actClaim, err := s.oboService.ResolveAgent(r.Context(), actorToken, actorTokenType, client.ID)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	perms, hash, err := s.oboService.ComputePerms(subject, actClaim, rar)
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
		Sub:                   subject,
		Act:                   actClaim,
		AuthorizationDetails:  rar,
		Perm:                  perms,
		HumanEntitlementsHash: hash,
	}

	token, expiresIn, err := s.oboService.IssueOBOToken(r.Context(), claims)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", err.Error())
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

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(start))
	})
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
