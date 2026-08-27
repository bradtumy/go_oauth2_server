package tatidp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	internaljwt "tokenator/internal/jwt"
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
	testIssuer     = "https://login.acme.example"
	testTenantHost = "tenant.example.com"
)

func newTestHandler(t *testing.T, tenantHost string) *Handler {
	t.Helper()

	keySet, err := internaljwt.LoadKeySetFromPEM([]byte(testSigningKeyPEM), "tat-test-key")
	if err != nil {
		t.Fatalf("load key set: %v", err)
	}
	signer, err := internaljwt.NewSignerWithKeySet(testIssuer, testTenantHost, keySet, time.Hour, time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("init signer: %v", err)
	}
	h, err := NewHandlerWithTemplates(signer, testIssuer, tenantHost, 5*time.Minute,
		filepath.Join("..", "..", "web", "templates"))
	if err != nil {
		t.Fatalf("init handler: %v", err)
	}
	return h
}

// TestMintedTATVerifiesAgainstPublishedKey is the contract the tenant depends
// on: the tenant is configured with the issuer string and the public key served
// at /tat/public-key.pem, and rejects the token if either fails to line up.
//
// The audience must be the tenant, and the issuer the configured TAT issuer —
// neither is tokenator's own identity, which is why this path signs raw claims
// instead of going through the normal access-token issuer.
func TestMintedTATVerifiesAgainstPublishedKey(t *testing.T) {
	h := newTestHandler(t, testTenantHost)

	form := url.Values{}
	form.Set("name", "Alice Anderson")
	form.Set("email", "alice@example.com")
	form.Set("nonce", "tenant-nonce-1")

	req := httptest.NewRequest(http.MethodPost, "/tat/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.HandleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	token := extractHiddenInput(t, rec.Body.String(), "token")
	if token == "" {
		t.Fatal("callback page carried no token")
	}

	// Verify exactly as the tenant would: with the published public key.
	pub := publishedPublicKey(t, h)
	parsed, err := jwt.Parse(token, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(testIssuer),
		jwt.WithAudience("https://"+testTenantHost),
	)
	if err != nil {
		t.Fatalf("tenant-side verification failed: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		t.Fatal("token did not yield valid claims")
	}

	if claims["sub"] != "alice@example.com" {
		t.Errorf("sub = %v, want alice@example.com", claims["sub"])
	}
	if claims["email"] != "alice@example.com" {
		t.Errorf("email = %v", claims["email"])
	}
	if claims["name"] != "Alice Anderson" {
		t.Errorf("name = %v", claims["name"])
	}
	if claims["nonce"] != "tenant-nonce-1" {
		t.Errorf("nonce = %v, want the value the tenant sent", claims["nonce"])
	}
	if _, ok := claims["exp"]; !ok {
		t.Error("token must carry exp")
	}
}

// TestCallbackPostsToTenant pins the form target, since the tenant only
// accepts the token at its own /SSO/Callback.
func TestCallbackPostsToTenant(t *testing.T) {
	h := newTestHandler(t, testTenantHost)

	form := url.Values{}
	form.Set("name", "Bob")
	form.Set("email", "bob@example.com")
	req := httptest.NewRequest(http.MethodPost, "/tat/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.HandleLogin(rec, req)

	body := rec.Body.String()
	want := "https://" + testTenantHost + "/SSO/Callback"
	if !strings.Contains(body, want) {
		t.Fatalf("callback page does not post to %s", want)
	}
}

// TestUnknownParamsRoundTrip covers the tenant handshake values whose names we
// do not know ahead of time: they arrive on the login request and must survive
// to the callback POST.
func TestUnknownParamsRoundTrip(t *testing.T) {
	h := newTestHandler(t, testTenantHost)

	form := url.Values{}
	form.Set("name", "Carol")
	form.Set("email", "carol@example.com")
	form.Set("RelayState", "tenant-relay-abc")
	form.Set("request_id", "req-42")

	req := httptest.NewRequest(http.MethodPost, "/tat/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.HandleLogin(rec, req)

	body := rec.Body.String()
	for _, want := range []string{"tenant-relay-abc", "req-42"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected passthrough value %q to survive to the callback", want)
		}
	}
	// The credentials themselves must not be echoed into the tenant POST.
	if strings.Contains(body, `name="email"`) {
		t.Error("email should not be forwarded as a passthrough field")
	}
}

// TestDisabledWithoutTenantHost keeps the feature inert until configured,
// rather than minting tokens with an empty audience.
func TestDisabledWithoutTenantHost(t *testing.T) {
	h := newTestHandler(t, "")

	for name, fn := range map[string]http.HandlerFunc{
		"show":  h.ShowLogin,
		"login": h.HandleLogin,
	} {
		rec := httptest.NewRecorder()
		fn(rec, httptest.NewRequest(http.MethodGet, "/tat/login", nil))
		if rec.Code != http.StatusPreconditionFailed {
			t.Errorf("%s: expected 412 when unconfigured, got %d", name, rec.Code)
		}
	}
}

func TestLoginRequiresNameAndEmail(t *testing.T) {
	h := newTestHandler(t, testTenantHost)

	for _, form := range []url.Values{
		{"email": {"only@example.com"}},
		{"name": {"Only Name"}},
		{},
	} {
		req := httptest.NewRequest(http.MethodPost, "/tat/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.HandleLogin(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("form %v: expected 400, got %d", form, rec.Code)
		}
	}
}

func TestPublicKeyPEMIsParseable(t *testing.T) {
	h := newTestHandler(t, testTenantHost)

	rec := httptest.NewRecorder()
	h.PublicKeyPEM(rec, httptest.NewRequest(http.MethodGet, "/tat/public-key.pem", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/x-pem-file" {
		t.Errorf("unexpected content type %q", got)
	}
	block, _ := pem.Decode(rec.Body.Bytes())
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("response was not a PEM public key")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Fatalf("public key does not parse: %v", err)
	}
}

func publishedPublicKey(t *testing.T, h *Handler) *rsa.PublicKey {
	t.Helper()
	rec := httptest.NewRecorder()
	h.PublicKeyPEM(rec, httptest.NewRequest(http.MethodGet, "/tat/public-key.pem", nil))
	block, _ := pem.Decode(rec.Body.Bytes())
	if block == nil {
		t.Fatal("no PEM block served")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected an RSA public key, got %T", parsed)
	}
	return pub
}

// extractHiddenInput pulls a hidden form field's value out of the callback page.
func extractHiddenInput(t *testing.T, body, field string) string {
	t.Helper()
	marker := `name="` + field + `"`
	idx := strings.Index(body, marker)
	if idx == -1 {
		return ""
	}
	rest := body[idx:]
	valueIdx := strings.Index(rest, `value="`)
	if valueIdx == -1 {
		return ""
	}
	rest = rest[valueIdx+len(`value="`):]
	end := strings.Index(rest, `"`)
	if end == -1 {
		return ""
	}
	return rest[:end]
}
