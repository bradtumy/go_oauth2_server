package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"go_oauth2_server/internal/config"
	"go_oauth2_server/internal/identity"
	internaljwt "go_oauth2_server/internal/jwt"
	"go_oauth2_server/internal/obo"
	"go_oauth2_server/internal/store"
	memstore "go_oauth2_server/internal/store/mem"
)

func TestAuthorizationCodeFlowWithRegisteredHuman(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "alice@example.com", Name: "Alice", TenantID: "default"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := fmt.Sprintf("%s/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&human_id=%s", server.URL, url.QueryEscape(srv.cfg.DefaultClientID), url.QueryEscape("http://localhost/callback"), url.QueryEscape(human.ID))
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302, got %d", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatal("expected authorization code")
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", srv.cfg.DefaultClientID)
	form.Set("client_secret", srv.cfg.DefaultClientSecret)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	access, _ := tokenResp["access_token"].(string)
	if access == "" {
		t.Fatal("missing access token")
	}
	claims, err := srv.signer.Verify(access, srv.cfg.Audience)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims["sub"] != human.ID {
		t.Fatalf("expected sub %s, got %v", human.ID, claims["sub"])
	}
	if claims["email"] != human.Email {
		t.Fatalf("expected email claim")
	}
}

func TestTokenExchangeWithRegisteredIdentities(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "bob@example.com", Name: "Bob", TenantID: "demo"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}
	agent, err := idStore.CreateAgent(ctx, identity.Agent{Name: "Worker", ClientID: "client-xyz", AgentID: "worker", Capabilities: []string{"orders:export"}})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	subjectBody, _ := json.Marshal(map[string]string{"human_id": human.ID})
	subjectResp, err := http.Post(server.URL+"/subject-assertion", "application/json", bytes.NewReader(subjectBody))
	if err != nil {
		t.Fatalf("subject assertion request: %v", err)
	}
	defer subjectResp.Body.Close()
	if subjectResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from subject assertion, got %d", subjectResp.StatusCode)
	}
	var subject map[string]any
	if err := json.NewDecoder(subjectResp.Body).Decode(&subject); err != nil {
		t.Fatalf("decode subject assertion: %v", err)
	}
	subjectToken, _ := subject["assertion"].(string)
	if subjectToken == "" {
		t.Fatal("missing subject assertion")
	}

	authDetails := `[{"type":"agent-action","actions":["orders:export"],"constraints":{"resource_ids":["acct:123"]}}]`
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", srv.cfg.Audience)
	form.Set("client_id", srv.cfg.DefaultClientID)
	form.Set("client_secret", srv.cfg.DefaultClientSecret)
	form.Set("authorization_details", authDetails)
	form.Set("agent_id", agent.AgentID)
	resp, err := http.PostForm(server.URL+"/token", form)
	if err != nil {
		t.Fatalf("obo request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode obo response: %v", err)
	}
	access, _ := tokenResp["access_token"].(string)
	if access == "" {
		t.Fatal("missing OBO access token")
	}
	claims, err := srv.signer.Verify(access, srv.cfg.Audience)
	if err != nil {
		t.Fatalf("verify obo token: %v", err)
	}
	if claims["sub"] != human.ID {
		t.Fatalf("expected sub %s, got %v", human.ID, claims["sub"])
	}
	act, ok := claims["act"].(map[string]any)
	if !ok || act["actor"] != agent.ID {
		t.Fatalf("expected act.actor %s, got %#v", agent.ID, act)
	}
	perms, ok := tokenResp["perm"].([]any)
	if !ok || len(perms) == 0 {
		t.Fatalf("expected perm in response")
	}
}

func TestTokenExchangeCapabilityDenied(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "charlie@example.com", Name: "Charlie"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}
	if _, err := idStore.CreateAgent(ctx, identity.Agent{Name: "Limited", ClientID: "client-xyz", Capabilities: []string{"orders:read"}}); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	subjectBody, _ := json.Marshal(map[string]string{"human_id": human.ID})
	subjectResp, err := http.Post(server.URL+"/subject-assertion", "application/json", bytes.NewReader(subjectBody))
	if err != nil {
		t.Fatalf("subject assertion request: %v", err)
	}
	defer subjectResp.Body.Close()
	var subject map[string]any
	if err := json.NewDecoder(subjectResp.Body).Decode(&subject); err != nil {
		t.Fatalf("decode subject assertion: %v", err)
	}
	subjectToken, _ := subject["assertion"].(string)

	authDetails := `[{"type":"agent-action","actions":["orders:export"]}]`
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", srv.cfg.Audience)
	form.Set("client_id", srv.cfg.DefaultClientID)
	form.Set("client_secret", srv.cfg.DefaultClientSecret)
	form.Set("authorization_details", authDetails)
	resp, err := http.PostForm(server.URL+"/token", form)
	if err != nil {
		t.Fatalf("obo request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestTokenExchangeActorMismatch(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "eve@example.com", Name: "Eve"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}
	if _, err := idStore.CreateAgent(ctx, identity.Agent{Name: "Worker", ClientID: "client-xyz", AgentID: "worker", Capabilities: []string{"orders:export"}}); err != nil {
		t.Fatalf("create agent: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	subjectBody, _ := json.Marshal(map[string]string{"human_id": human.ID})
	subjectResp, err := http.Post(server.URL+"/subject-assertion", "application/json", bytes.NewReader(subjectBody))
	if err != nil {
		t.Fatalf("subject assertion request: %v", err)
	}
	defer subjectResp.Body.Close()
	if subjectResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from subject assertion, got %d", subjectResp.StatusCode)
	}
	var subject map[string]any
	if err := json.NewDecoder(subjectResp.Body).Decode(&subject); err != nil {
		t.Fatalf("decode subject assertion: %v", err)
	}
	subjectToken, _ := subject["assertion"].(string)
	if subjectToken == "" {
		t.Fatal("missing subject assertion")
	}

	actorToken, _, err := srv.signer.IssueAccessWithClaims(ctx, "agent:notfound", srv.cfg.DefaultClientID, "", map[string]any{"actor": "agent:notfound"})
	if err != nil {
		t.Fatalf("issue actor token: %v", err)
	}

	authDetails := `[{"type":"agent-action","actions":["orders:export"],"constraints":{"resource_ids":["acct:123"]}}]`
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("actor_token", actorToken)
	form.Set("actor_token_type", "urn:ietf:params:oauth:token-type:jwt")
	form.Set("audience", srv.cfg.Audience)
	form.Set("client_id", srv.cfg.DefaultClientID)
	form.Set("client_secret", srv.cfg.DefaultClientSecret)
	form.Set("authorization_details", authDetails)

	resp, err := http.PostForm(server.URL+"/token", form)
	if err != nil {
		t.Fatalf("obo request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, string(body))
	}
	var oauthErr map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if got, want := oauthErr["error"], "invalid_request"; got != want {
		t.Fatalf("expected error %q, got %v", want, got)
	}
}

func TestTokenExchangeInvalidSubjectToken(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	if _, err := idStore.CreateHuman(ctx, identity.Human{Email: "dana@example.com", Name: "Dana"}); err != nil {
		t.Fatalf("create human: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", "not-a-token")
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("scope", "orders:export")
	form.Set("client_id", srv.cfg.DefaultClientID)
	form.Set("client_secret", srv.cfg.DefaultClientSecret)

	resp, err := http.PostForm(server.URL+"/token", form)
	if err != nil {
		t.Fatalf("obo request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, string(body))
	}
	var oauthErr map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&oauthErr); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if got, want := oauthErr["error"], "invalid_grant"; got != want {
		t.Fatalf("expected error %q, got %v", want, got)
	}
}

func newTestServer(t *testing.T, identityStore identity.Store) (*authorizationServer, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{
		Issuer:              "http://test-as",
		Audience:            "http://test-rs",
		SigningKey:          []byte("12345678901234567890"),
		SigningKeyID:        "test-key",
		DefaultClientID:     "client-xyz",
		DefaultClientSecret: "secret-xyz",
		CodeTTL:             time.Minute,
		AccessTokenTTL:      time.Hour,
		RefreshTokenTTL:     time.Hour,
		OBOTokenTTL:         time.Minute,
	}
	defaultClient := store.Client{
		ID:           cfg.DefaultClientID,
		Secret:       cfg.DefaultClientSecret,
		RedirectURI:  "http://localhost/callback",
		Audience:     cfg.Audience,
		DefaultScope: "openid",
	}
	oauthStore := store.New(defaultClient)
	signer := internaljwt.NewSigner(cfg.Issuer, cfg.Audience, cfg.SigningKey, cfg.SigningKeyID, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.OBOTokenTTL)
	oboService := &obo.Service{Signer: signer, Issuer: cfg.Issuer, Audience: cfg.Audience, OBOTTL: cfg.OBOTokenTTL}

	srv := &authorizationServer{
		cfg:                cfg,
		store:              oauthStore,
		signer:             signer,
		oboService:         oboService,
		identities:         identityStore,
		allowLegacy:        false,
		legacyUsers:        map[string]string{},
		legacyDefaultHuman: "",
	}

	identityHandler := identity.NewHandler(identityStore, cfg.AdminToken)
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", methodHandler(http.MethodGet, srv.handleAuthorize))
	mux.HandleFunc("/token", methodHandler(http.MethodPost, srv.handleToken))
	mux.HandleFunc("/subject-assertion", methodHandler(http.MethodPost, srv.handleSubjectAssertion))
	mux.HandleFunc("/register/human", methodHandler(http.MethodPost, identityHandler.CreateHuman))
	mux.HandleFunc("/register/agent", methodHandler(http.MethodPost, identityHandler.CreateAgent))

	server := httptest.NewServer(loggingMiddleware(mux))
	return srv, server
}
