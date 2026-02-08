package main

import (
	"bytes"
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

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&human_id=%s", server.URL, url.QueryEscape(testClientID), url.QueryEscape("http://localhost/callback"), url.QueryEscape(human.ID))
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
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	req, err := http.NewRequest(http.MethodPost, server.URL+"/oauth2/token", strings.NewReader(form.Encode()))
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

	_, server := newTestServer(t, idStore)
	defer server.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&human_id=%s", server.URL, url.QueryEscape(testClientID), url.QueryEscape("http://localhost/other"), url.QueryEscape(human.ID))
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
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

	_, server := newTestServer(t, idStore)
	defer server.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&human_id=%s", server.URL, url.QueryEscape(testClientID), url.QueryEscape("http://localhost/callback"), url.QueryEscape(human.ID))
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer resp.Body.Close()
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
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	resp, err = http.PostForm(server.URL+"/oauth2/token", form)
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
	}
	_, server := newTestServerWithConfig(t, idStore, cfg)
	defer server.Close()

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=openid&human_id=%s", server.URL, url.QueryEscape(testClientID), url.QueryEscape("http://localhost/callback"), url.QueryEscape(human.ID))
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer resp.Body.Close()
	location := resp.Header.Get("Location")
	locURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}
	code := locURL.Query().Get("code")
	if code == "" {
		t.Fatal("expected authorization code")
	}

	time.Sleep(20 * time.Millisecond)

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", "http://localhost/callback")
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	resp, err = http.PostForm(server.URL+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
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

	client := &http.Client{CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	authURL := fmt.Sprintf("%s/oauth2/authorize?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&human_id=%s", server.URL, url.QueryEscape(testClientID), url.QueryEscape("http://localhost/callback"), url.QueryEscape("orders:read"), url.QueryEscape(human.ID))
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	defer resp.Body.Close()
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
	form.Set("client_id", testClientID)
	form.Set("client_secret", testClientSecret)
	resp, err = http.PostForm(server.URL+"/oauth2/token", form)
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
	}
	return newTestServerWithConfig(t, identityStore, cfg)
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
	signer, err := internaljwt.NewSigner(cfg.Issuer, cfg.Audience, cfg.SigningKeyPEM, cfg.SigningKeyID, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.OBOTokenTTL)
	if err != nil {
		t.Fatalf("init signer: %v", err)
	}
	oboService := &obo.Service{Signer: signer, Issuer: cfg.Issuer, Audience: cfg.Audience, OBOTTL: cfg.OBOTokenTTL}

	srv := &authorizationServer{
		cfg:                cfg,
		store:              oauthStore,
		clients:            clientStore,
		signer:             signer,
		oboService:         oboService,
		identities:         identityStore,
		allowLegacy:        false,
		legacyUsers:        map[string]string{},
		legacyDefaultHuman: "",
	}

	identityHandler := identity.NewHandler(identityStore, cfg.AdminToken)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", methodHandler(http.MethodGet, srv.handleJWKS))
	mux.HandleFunc("/authorize", methodHandler(http.MethodGet, srv.handleAuthorize))
	mux.HandleFunc("/token", methodHandler(http.MethodPost, srv.handleToken))
	mux.HandleFunc("/oauth2/authorize", methodHandler(http.MethodGet, srv.handleAuthorize))
	mux.HandleFunc("/oauth2/token", methodHandler(http.MethodPost, srv.handleToken))
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
