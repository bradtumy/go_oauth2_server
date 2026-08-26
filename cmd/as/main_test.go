package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tokenator/internal/auth"
	"tokenator/internal/config"
	"tokenator/internal/identity"
	internaljwt "tokenator/internal/jwt"
	"tokenator/internal/obo"
	"tokenator/internal/ratelimit"
	"tokenator/internal/session"
	"tokenator/internal/store"
	memstore "tokenator/internal/store/mem"
)

const testSigningKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCk3F5CWCLo296k
DRBCPt2wuhc9wbAdotnCt6prj+Ue4vQGFXzqybvqEr+M7g8YFOOIGA0jdoWMg7to
ztgLyLqjrq9LWVWI4ZeMalweI8wAQcT49EDrC7d/QITMeie/bQiXDMZOshE6eKkv
N1qjax1tgxiQW2vJNIGuZz3g0ytCjK+2HXxovkkzOm59FEzQ87gYwGQR75AAqnmt
Fa8eFXPGpa7eMSa+yJeQFjX4nQ1e16wnhueibheoJggrSSM+fkO9u5AWg+Synrld
ETb4iMP9ftQW9knkiaABFSGkZ/paMuWhzxaRSym+Z1Cf5amUpqKx0Bi/Ut5lVRJV
RpJA+6qFAgMBAAECggEAP0QKMC+ehfoKgK46tRFnBfEEBkEUEutx4dWV4t0/shCq
UMNiQr/UC0nSlISu6jDp+EoykI9lRL0w6FGoey024qWgw6uutW7NN6eBXleia97R
djBV0V2Xt4/M5qNiKYXwK/dNCtou3l97nZECiYALtQEAJjXPMVGjCoi4KFUhXtH7
yQHfCkoyRyPnIU3aYwzqXdaejyp2uCmLzprpPcg0NoFLh8lASSWUybPws3nEk7Bq
qGfGL9eGSm28gNCMu8O8CDWApOPfAyNi6CWbDBY5xf1uow/q2xX5V5bTPZwC3HsO
HtIiu6+JWcdlYifLUorYwuCeWAt2B7Nn0tsbpH5KKQKBgQDmnjZAms9XsfJ2/t43
L0LQTvx1H9iQUD0sghs1oWDifuAk+KrvfrzX6Cbvqw4dF/CWIl0segSkDHVZwQjP
FVMekQ4fnXTG6OsQeyjrjB2NWhM2oizY7FxzobEu/rhE+DpmlsFLlg80b6ZI+suJ
avAVo82W1rSxedYLd8dEAZIqEwKBgQC3AWlMqLob5ZUZlINyjlZ7VY1+EEUmtXPg
mRD97aLQxO/NG3G8LtMSs/VwXkRy25YZVIN2ZJe5QLsiwSspQ3yJuPfb5bQjWw2E
0CZvW7ZgRJoBFR6jxb3aLAvUoqPqokL6wlVA5VjGP0t4xzCBFVATn3kUWzbWlz2k
aXfpImHsBwKBgQCf0kEy4JaU5cNs6BBEGkKpbjPTT7Cbwp/CeqA0uJQWI2te894y
f5iL4F0rd1Yen3qh8Uq1ChKxRdkFzJs4OEUUR96L1mkZeE1/bHrdUosgbK4oDJgb
9SHVGNdcBDbbxVNjyVJH+cSryDxrEzN/FlcwCAbwY/dxj0fhRq8X2CbddQKBgCXC
+cpiqnxlJB3yIil6K2gpoBeaHdq96Fo422O6LDVt3ZlyB0bwVoducL+uA+u7Wb6C
TNoaKaCFNdgXCePq1ADLFQHf5QrCmAiGtteVkg1NOoXsqLTcca9aFVrb8HzS3IVH
ojXQ3T+TAey7FUwdbLeP2XkU1Tz0WjjZtm95s8DzAoGBAKMKN05H4h2s74TC3EJB
ud70LksnQheSBameXDdKe0t9ocCqYlR3L4ECIE3/qPEeHR+esphI9s4WgivGVZEL
s8Db464pzs9t0Z/+RowMN8nMuwXoybwSJYCdm83GEevJoZ4av5gaJCvIEjGHNCul
odOEQaR0ILGMQJZmpfvekDyK
-----END PRIVATE KEY-----`

const (
	testClientID     = "client-xyz"
	testClientSecret = "secret-xyz"
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

	code := authorizeCode(t, srv, server, human, authorizeParams(testClientID, "http://localhost/callback", "openid"))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
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

func TestPublicClientRequiresPKCE(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "pkce@example.com", Name: "PKCE User"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	_, err = srv.clients.CreateClient(ctx, store.Client{
		ID:           "public-client",
		Type:         store.ClientTypePublic,
		RedirectURIs: []string{"http://localhost/callback"},
		GrantTypes:   []string{store.GrantAuthorizationCode},
		Scopes:       []string{"openid"},
	})
	if err != nil {
		t.Fatalf("seed public client: %v", err)
	}

	noPKCE := authorizeParams("public-client", "http://localhost/callback", "openid")
	resp := authorizeWithConsent(t, srv, server, human, noPKCE)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 without PKCE, got %d", resp.StatusCode)
	}

	codeVerifier := "pkce-code-verifier-1234567890abcdef1234567890abcdef1234567"
	challenge := pkceChallenge(codeVerifier)

	plainPKCE := authorizeParams("public-client", "http://localhost/callback", "openid")
	plainPKCE.Set("code_challenge", challenge)
	plainPKCE.Set("code_challenge_method", "plain")
	resp = authorizeWithConsent(t, srv, server, human, plainPKCE)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for plain PKCE, got %d", resp.StatusCode)
	}

	s256PKCE := authorizeParams("public-client", "http://localhost/callback", "openid")
	s256PKCE.Set("code_challenge", challenge)
	s256PKCE.Set("code_challenge_method", "S256")
	code := authorizeCode(t, srv, server, human, s256PKCE)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", "public-client")
	form.Set("code_verifier", codeVerifier)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestRefreshTokenRotationAndReuseDetection(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "refresh@example.com", Name: "Refresh User"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	code := authorizeCode(t, srv, server, human, authorizeParams(testClientID, "http://localhost/callback", "openid"))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	refresh, _ := tokenResp["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("missing refresh token")
	}

	refreshForm := url.Values{}
	refreshForm.Set("grant_type", "refresh_token")
	refreshForm.Set("refresh_token", refresh)
	refreshForm.Set("client_id", testClientID)
	refreshForm.Set("client_secret", testClientSecret)
	resp, err = http.PostForm(server.URL+"/oauth2/token", refreshForm)
	if err != nil {
		t.Fatalf("refresh request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	var refreshResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&refreshResp); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	newRefresh, _ := refreshResp["refresh_token"].(string)
	if newRefresh == "" {
		t.Fatal("missing rotated refresh token")
	}
	if newRefresh == refresh {
		t.Fatal("refresh token did not rotate")
	}

	resp, err = http.PostForm(server.URL+"/oauth2/token", refreshForm)
	if err != nil {
		t.Fatalf("refresh request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 on reuse, got %d", resp.StatusCode)
	}

	refreshForm.Set("refresh_token", newRefresh)
	resp, err = http.PostForm(server.URL+"/oauth2/token", refreshForm)
	if err != nil {
		t.Fatalf("refresh request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 after family revoke, got %d", resp.StatusCode)
	}
}

func TestIntrospectAndRevoke(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "introspect@example.com", Name: "Introspect User"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	code := authorizeCode(t, srv, server, human, authorizeParams(testClientID, "http://localhost/callback", "openid"))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("create token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	refresh, _ := tokenResp["refresh_token"].(string)
	if refresh == "" {
		t.Fatal("missing refresh token")
	}

	introspectForm := url.Values{}
	introspectForm.Set("token", refresh)
	introspectForm.Set("token_type_hint", "refresh_token")
	introspectForm.Set("client_id", testClientID)
	introspectForm.Set("client_secret", testClientSecret)
	resp, err = http.PostForm(server.URL+"/oauth2/introspect", introspectForm)
	if err != nil {
		t.Fatalf("introspect request: %v", err)
	}
	defer resp.Body.Close()
	var introspectResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&introspectResp); err != nil {
		t.Fatalf("decode introspect response: %v", err)
	}
	if active, _ := introspectResp["active"].(bool); !active {
		t.Fatal("expected refresh token active")
	}

	revokeForm := url.Values{}
	revokeForm.Set("token", refresh)
	revokeForm.Set("token_type_hint", "refresh_token")
	revokeForm.Set("client_id", testClientID)
	revokeForm.Set("client_secret", testClientSecret)
	resp, err = http.PostForm(server.URL+"/oauth2/revoke", revokeForm)
	if err != nil {
		t.Fatalf("revoke request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	resp, err = http.PostForm(server.URL+"/oauth2/introspect", introspectForm)
	if err != nil {
		t.Fatalf("introspect request: %v", err)
	}
	defer resp.Body.Close()
	introspectResp = map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&introspectResp); err != nil {
		t.Fatalf("decode introspect response: %v", err)
	}
	if active, _ := introspectResp["active"].(bool); active {
		t.Fatal("expected refresh token inactive after revoke")
	}
}

func TestTokenRateLimit(t *testing.T) {
	idStore := memstore.New()

	cfg := &config.Config{
		Issuer:          "http://test-as",
		Audience:        "http://test-rs",
		SigningKeyPEM:   []byte(testSigningKeyPEM),
		SigningKeyID:    "test-key",
		CodeTTL:         time.Minute,
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: time.Hour,
		OBOTokenTTL:     time.Minute,
	}
	srv, warmServer := newTestServerWithConfig(t, idStore, cfg)
	warmServer.Close()

	limiter := ratelimit.NewLimiter(1, 1)
	mux := http.NewServeMux()
	mux.Handle("/oauth2/token", rateLimitMiddleware(limiter, methodHandler(http.MethodPost, srv.handleToken)))
	rateServer := httptest.NewServer(loggingMiddleware(mux))
	defer rateServer.Close()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	resp, err := http.PostForm(rateServer.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	resp, err = http.PostForm(rateServer.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", resp.StatusCode)
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

	subjectToken := mintScopedAccessToken(t, srv, server, human, "orders:export")

	authDetails := `[{"type":"agent-action","actions":["orders:export"],"constraints":{"resource_ids":["acct:123"]}}]`
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", srv.cfg.Audience)
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	form.Set("authorization_details", authDetails)
	form.Set("agent_id", agent.AgentID)
	resp, err := http.PostForm(server.URL+"/oauth2/token", form)
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

	// The human genuinely holds orders:export; the agent's capabilities do not,
	// so the exchange must be refused on capability grounds, not scope grounds.
	subjectToken := mintScopedAccessToken(t, srv, server, human, "orders:export")

	authDetails := `[{"type":"agent-action","actions":["orders:export"]}]`
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", subjectToken)
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("audience", srv.cfg.Audience)
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	form.Set("authorization_details", authDetails)
	resp, err := http.PostForm(server.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("obo request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestTokenExchangeInvalidSubjectToken(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	if _, err := idStore.CreateHuman(ctx, identity.Human{Email: "dana@example.com", Name: "Dana"}); err != nil {
		t.Fatalf("create human: %v", err)
	}

	_, server := newTestServer(t, idStore)
	defer server.Close()

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	form.Set("subject_token", "not-a-token")
	form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	form.Set("scope", "orders:export")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)

	resp, err := http.PostForm(server.URL+"/oauth2/token", form)
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

func TestRedirectURIMismatch(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "eve@example.com", Name: "Eve"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	resp := authorizeWithConsent(t, srv, server, human, authorizeParams(testClientID, "http://localhost/other", "openid"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAuthorizationCodeOneTimeUse(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "frank@example.com", Name: "Frank"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	code := authorizeCode(t, srv, server, human, authorizeParams(testClientID, "http://localhost/callback", "openid"))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	resp, err := http.PostForm(server.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	resp.Body.Close()

	resp, err = http.PostForm(server.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("second token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

func TestAuthorizationCodeExpires(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "gina@example.com", Name: "Gina"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	cfg := &config.Config{
		Issuer:          "http://test-as",
		Audience:        "http://test-rs",
		SigningKeyPEM:   []byte(testSigningKeyPEM),
		SigningKeyID:    "test-key",
		CodeTTL:         10 * time.Millisecond,
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: time.Hour,
		OBOTokenTTL:     time.Minute,
		EnableRAR:       true,
	}
	srv, server := newTestServerWithConfig(t, idStore, cfg)
	defer server.Close()

	code := authorizeCode(t, srv, server, human, authorizeParams(testClientID, "http://localhost/callback", "openid"))

	time.Sleep(20 * time.Millisecond)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	resp, err := http.PostForm(server.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
}

// TestMetadataAdvertisesSupportedClientAuth guards the discovery documents
// against drifting away from what the server actually implements: RFC 7523
// client assertions and RFC 9449 DPoP were both shipped without ever being
// announced, leaving conforming clients unable to discover them.
func TestMetadataAdvertisesSupportedClientAuth(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	if _, err := idStore.CreateHuman(ctx, identity.Human{Email: "meta@example.com", Name: "Meta"}); err != nil {
		t.Fatalf("create human: %v", err)
	}

	_, server := newTestServer(t, idStore)
	defer server.Close()

	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		resp, err := http.Get(server.URL + path)
		if err != nil {
			t.Fatalf("%s: request: %v", path, err)
		}
		var metadata map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
			resp.Body.Close()
			t.Fatalf("%s: decode: %v", path, err)
		}
		resp.Body.Close()

		methods := toStringSlice(metadata["token_endpoint_auth_methods_supported"])
		if !stringInList(methods, "private_key_jwt") {
			t.Errorf("%s: expected private_key_jwt in token_endpoint_auth_methods_supported, got %v", path, methods)
		}
		if !stringInList(toStringSlice(metadata["token_endpoint_auth_signing_alg_values_supported"]), "RS256") {
			t.Errorf("%s: expected RS256 among client assertion signing algs", path)
		}
		if !stringInList(toStringSlice(metadata["dpop_signing_alg_values_supported"]), "ES256") {
			t.Errorf("%s: expected ES256 among DPoP signing algs", path)
		}
	}
}

func toStringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func TestJWKSAndJWTClaims(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	if _, err := idStore.CreateHuman(ctx, identity.Human{Email: "henry@example.com", Name: "Henry"}); err != nil {
		t.Fatalf("create human: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	form.Set("scope", "orders:export")
	resp, err := http.PostForm(server.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	access, _ := tokenResp["access_token"].(string)
	if access == "" {
		t.Fatal("missing access token")
	}

	jwksResp, err := http.Get(server.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("jwks request: %v", err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", jwksResp.StatusCode)
	}
	var jwks map[string]any
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	key := jwksFirstKey(t, jwks)
	if key["kid"] == "" {
		t.Fatal("expected kid in jwks")
	}
	if key["alg"] != "RS256" {
		t.Fatalf("expected RS256 alg, got %v", key["alg"])
	}

	claims, err := verifyWithJWKS(access, key)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims["iss"] != srv.cfg.Issuer || claims["aud"] != srv.cfg.Audience {
		t.Fatalf("unexpected iss/aud: %v %v", claims["iss"], claims["aud"])
	}
	for _, field := range []string{"sub", "exp", "iat"} {
		if _, ok := claims[field]; !ok {
			t.Fatalf("missing %s claim", field)
		}
	}
}

func TestTokenExchangeScopeEscalationDenied(t *testing.T) {
	ctx := context.Background()
	idStore := memstore.New()
	human, err := idStore.CreateHuman(ctx, identity.Human{Email: "ian@example.com", Name: "Ian"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	srv, server := newTestServer(t, idStore)
	defer server.Close()

	code := authorizeCode(t, srv, server, human, authorizeParams(testClientID, "http://localhost/callback", "orders:read"))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	resp, err := http.PostForm(server.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	subjectToken, _ := tokenResp["access_token"].(string)
	if subjectToken == "" {
		t.Fatal("missing access token")
	}

	exchange := url.Values{}
	exchange.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	exchange.Set("subject_token", subjectToken)
	exchange.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
	exchange.Set("audience", srv.cfg.Audience)
	exchange.Set("client_id", testClientID)
	exchange.Set("client_secret", testClientSecret)
	exchange.Set("scope", "orders:export")
	resp, err = http.PostForm(server.URL+"/oauth2/token", exchange)
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400, got %d: %s", resp.StatusCode, string(body))
	}
}

func newTestServer(t *testing.T, identityStore identity.Store) (*authorizationServer, *httptest.Server) {
	t.Helper()
	cfg := &config.Config{
		Issuer:          "http://test-as",
		Audience:        "http://test-rs",
		SigningKeyPEM:   []byte(testSigningKeyPEM),
		SigningKeyID:    "test-key",
		CodeTTL:         time.Minute,
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: time.Hour,
		OBOTokenTTL:     time.Minute,
		EnableRAR:       true,
	}
	return newTestServerWithConfig(t, identityStore, cfg)
}

// mintScopedAccessToken runs a full authorization code flow for the human and
// returns an access token carrying scope, suitable for use as an RFC 8693
// subject token. Token exchange validates the requested scope against the
// subject token's scope, so the subject token must actually hold it.
func mintScopedAccessToken(t *testing.T, srv *authorizationServer, server *httptest.Server, human identity.Human, scope string) string {
	t.Helper()

	code := authorizeCode(t, srv, server, human, authorizeParams(testClientID, "http://localhost/callback", scope))

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	resp, err := http.PostForm(server.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200 minting subject token, got %d: %s", resp.StatusCode, string(body))
	}
	var tokenResp map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	access, _ := tokenResp["access_token"].(string)
	if access == "" {
		t.Fatal("missing access token for subject token")
	}
	return access
}

// authorizeParams builds a standard authorization request. Identity is carried
// by the session cookie, never by a query parameter.
func authorizeParams(clientID, redirectURI, scope string) url.Values {
	return url.Values{
		"response_type": {"code"},
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"scope":         {scope},
	}
}

// authorizeWithConsent drives the real end-to-end browser flow for an already
// authenticated human: it mints a session, calls GET /oauth2/authorize with the
// session cookie, then approves the resulting consent page via POST /consent.
//
// When the authorize step does not reach consent — a validation failure such as
// a missing PKCE challenge or a mismatched redirect_uri — that response is
// returned as-is so tests can assert on it. Otherwise the redirect produced by
// the consent approval is returned, carrying the authorization code.
//
// Callers must close the returned response body.
func authorizeWithConsent(t *testing.T, srv *authorizationServer, server *httptest.Server, human identity.Human, params url.Values) *http.Response {
	t.Helper()

	sess, err := srv.authHandler.Sessions.Create(human.ID, human.Email)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	cookie := &http.Cookie{Name: "session_id", Value: sess.ID}
	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}

	authReq, err := http.NewRequest(http.MethodGet, server.URL+"/oauth2/authorize?"+params.Encode(), nil)
	if err != nil {
		t.Fatalf("build authorize request: %v", err)
	}
	authReq.AddCookie(cookie)
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}

	// Anything other than a rendered consent page is the caller's to assert on.
	if authResp.StatusCode != http.StatusOK {
		return authResp
	}
	authResp.Body.Close()

	form := url.Values{}
	form.Set("action", "approve")
	for _, field := range []string{"client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"} {
		if v := params.Get(field); v != "" {
			form.Set(field, v)
		}
	}

	consentReq, err := http.NewRequest(http.MethodPost, server.URL+"/consent", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build consent request: %v", err)
	}
	consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	consentReq.AddCookie(cookie)
	consentResp, err := client.Do(consentReq)
	if err != nil {
		t.Fatalf("consent request: %v", err)
	}
	return consentResp
}

// authorizeCode runs authorizeWithConsent and extracts the authorization code
// from the resulting redirect, failing the test if one was not issued.
func authorizeCode(t *testing.T, srv *authorizationServer, server *httptest.Server, human identity.Human, params url.Values) string {
	t.Helper()

	resp := authorizeWithConsent(t, srv, server, human, params)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 302 from consent, got %d: %s", resp.StatusCode, string(body))
	}
	locURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatal("expected authorization code")
	}
	return code
}

func newTestServerWithConfig(t *testing.T, identityStore identity.Store, cfg *config.Config) (*authorizationServer, *httptest.Server) {
	oauthStore := store.New()
	clientStore := memstore.NewClientStore()
	_, err := clientStore.CreateClient(context.Background(), store.Client{
		ID:           testClientID,
		Type:         store.ClientTypeConfidential,
		Secret:       testClientSecret,
		RedirectURIs: []string{"http://localhost/callback"},
		GrantTypes: []string{
			store.GrantAuthorizationCode,
			store.GrantRefreshToken,
			store.GrantClientCredentials,
			store.GrantTokenExchange,
		},
		Scopes:    []string{"openid", "orders:read", "orders:export"},
		Audiences: []string{cfg.Audience},
	})
	if err != nil {
		t.Fatalf("seed client: %v", err)
	}
	keySet, err := internaljwt.LoadKeySetFromPEM(cfg.SigningKeyPEM, cfg.SigningKeyID)
	if err != nil {
		t.Fatalf("init signer: %v", err)
	}
	signer, err := internaljwt.NewSignerWithKeySet(cfg.Issuer, cfg.Audience, keySet, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.OBOTokenTTL)
	if err != nil {
		t.Fatalf("init signer: %v", err)
	}
	oboService := &obo.Service{Signer: signer, Issuer: cfg.Issuer, Audience: cfg.Audience, OBOTTL: cfg.OBOTokenTTL}

	sessionStore := session.NewMemoryStore(0)
	authHandler, err := auth.NewHandlerWithTemplates(sessionStore, identityStore, cfg.DevMode, filepath.Join("..", "..", "web", "templates"))
	if err != nil {
		t.Fatalf("init auth handler: %v", err)
	}

	srv := &authorizationServer{
		cfg:                cfg,
		store:              oauthStore,
		clients:            clientStore,
		signer:             signer,
		oboService:         oboService,
		identities:         identityStore,
		authHandler:        authHandler,
		allowLegacy:        false,
		legacyUsers:        map[string]string{},
		legacyDefaultHuman: "",
	}

	identityHandler := identity.NewHandler(identityStore, cfg.AdminToken)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", methodHandler(http.MethodGet, srv.handleJWKS))
	mux.HandleFunc("/.well-known/oauth-authorization-server", methodHandler(http.MethodGet, srv.handleAuthorizationServerMetadata))
	mux.HandleFunc("/.well-known/openid-configuration", methodHandler(http.MethodGet, srv.handleOpenIDConfiguration))
	// Mirror production routing: /authorize and /consent sit behind RequireAuth so
	// tests exercise the real session + consent path rather than a relaxed handler.
	mux.Handle("/authorize", authHandler.RequireAuth(methodHandler(http.MethodGet, srv.handleAuthorize)))
	mux.HandleFunc("/token", methodHandler(http.MethodPost, srv.handleToken))
	mux.Handle("/oauth2/authorize", authHandler.RequireAuth(methodHandler(http.MethodGet, srv.handleAuthorize)))
	mux.Handle("/consent", authHandler.RequireAuth(methodHandler(http.MethodPost, srv.handleConsent)))
	mux.HandleFunc("/oauth2/token", methodHandler(http.MethodPost, srv.handleToken))
	mux.HandleFunc("/oauth2/introspect", methodHandler(http.MethodPost, srv.handleIntrospect))
	mux.HandleFunc("/oauth2/revoke", methodHandler(http.MethodPost, srv.handleRevoke))
	mux.HandleFunc("/subject-assertion", methodHandler(http.MethodPost, srv.handleSubjectAssertion))
	mux.HandleFunc("/register/human", methodHandler(http.MethodPost, identityHandler.CreateHuman))
	mux.HandleFunc("/register/agent", methodHandler(http.MethodPost, identityHandler.CreateAgent))

	server := httptest.NewServer(loggingMiddleware(mux))
	return srv, server
}

func jwksFirstKey(t *testing.T, jwks map[string]any) map[string]any {
	keys, ok := jwks["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatal("jwks keys missing")
	}
	key, ok := keys[0].(map[string]any)
	if !ok {
		t.Fatal("jwks key invalid")
	}
	return key
}

func verifyWithJWKS(token string, jwk map[string]any) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	nRaw, _ := jwk["n"].(string)
	eRaw, _ := jwk["e"].(string)
	if nRaw == "" || eRaw == "" {
		return nil, fmt.Errorf("missing jwk params")
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(nRaw)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eRaw)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	eInt := 0
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: eInt}

	unsigned := strings.Join(parts[:2], ".")
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	hash := sha256.Sum256([]byte(unsigned))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hash[:], sigBytes); err != nil {
		return nil, fmt.Errorf("verify signature: %w", err)
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	return claims, nil
}

func pkceChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// TestSeedIdentitiesHashesPasswords covers the seeded-login path: identities are
// held in memory and reseeded on every boot, and a seeded human without a
// password hash can only sign in when DEV_MODE is on. Seeds carrying a password
// must therefore land as a verifiable bcrypt hash, never as plaintext.
func TestSeedIdentitiesHashesPasswords(t *testing.T) {
	seed := `{"humans":[
		{"email":"seeded@example.com","name":"Seeded","password":"s3cr3t-pass"},
		{"email":"nopass@example.com","name":"No Pass"}
	]}`
	path := filepath.Join(t.TempDir(), "identities.json")
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}

	ctx := context.Background()
	idStore := memstore.New()
	if err := seedIdentities(ctx, idStore, path); err != nil {
		t.Fatalf("seed identities: %v", err)
	}

	withPass, ok := idStore.GetHumanByEmail(ctx, "seeded@example.com")
	if !ok {
		t.Fatal("seeded human not found")
	}
	if withPass.PasswordHash == "" {
		t.Fatal("expected a password hash for a seeded human with a password")
	}
	if withPass.PasswordHash == "s3cr3t-pass" {
		t.Fatal("password was stored in plaintext")
	}
	if err := auth.VerifyPassword(withPass.PasswordHash, "s3cr3t-pass"); err != nil {
		t.Fatalf("seeded password does not verify: %v", err)
	}
	if err := auth.VerifyPassword(withPass.PasswordHash, "wrong"); err == nil {
		t.Fatal("expected wrong password to fail verification")
	}

	noPass, ok := idStore.GetHumanByEmail(ctx, "nopass@example.com")
	if !ok {
		t.Fatal("passwordless seeded human not found")
	}
	if noPass.PasswordHash != "" {
		t.Fatal("expected no password hash when the seed omits one")
	}
}
