package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	internaljwt "tokenator/internal/jwt"
)

const testRSSigningKeyPEM = `-----BEGIN PRIVATE KEY-----
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

// newTestResourceServer builds a resource server whose signer both mints and
// verifies tokens, so tests can issue a token with an arbitrary scope.
func newTestResourceServer(t *testing.T) (*resourceServer, *internaljwt.Signer) {
	t.Helper()

	cfg := &resourceConfig{
		Issuer:     "http://test-as",
		Audience:   "http://test-rs",
		KeyID:      "test-key",
		AccessTTL:  time.Hour,
		RefreshTTL: time.Hour,
	}

	keySet, err := internaljwt.LoadKeySetFromPEM([]byte(testRSSigningKeyPEM), cfg.KeyID)
	if err != nil {
		t.Fatalf("load key set: %v", err)
	}
	signer, err := internaljwt.NewSignerWithKeySet(cfg.Issuer, cfg.Audience, keySet, cfg.AccessTTL, cfg.RefreshTTL, cfg.AccessTTL)
	if err != nil {
		t.Fatalf("init signer: %v", err)
	}
	return &resourceServer{cfg: cfg, signer: signer}, signer
}

func mintScopedToken(t *testing.T, signer *internaljwt.Signer, scope string) string {
	t.Helper()
	token, _, err := signer.IssueAccess(context.Background(), "human-1", "human-web", scope)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return token
}

// TestRouteScopeRequirements pins each protected context to the scopes it
// actually documents.
//
// The /accounts/ context once required the orders scopes, copied from the
// /orders/ registration directly above it. The demo client requests
// tickets.read and calls /accounts/{id}/orders/export, so every run of the
// example flow ended in 403 "insufficient scope".
func TestRouteScopeRequirements(t *testing.T) {
	rs, signer := newTestResourceServer(t)
	mux := rs.routes()

	cases := []struct {
		name       string
		path       string
		tokenScope string
		wantStatus int
	}{
		{"accounts accepts tickets.read", "/accounts/12345/orders/export", "tickets.read", http.StatusOK},
		{"accounts accepts tickets.write", "/accounts/12345/orders/export", "tickets.write", http.StatusOK},
		{"accounts rejects orders.read", "/accounts/12345/orders/export", "orders.read", http.StatusForbidden},
		{"orders accepts orders.read", "/orders/12345/fields", "orders.read", http.StatusOK},
		{"orders rejects tickets.read", "/orders/12345/fields", "tickets.read", http.StatusForbidden},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			req.Header.Set("Authorization", "Bearer "+mintScopedToken(t, signer, tc.tokenScope))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)

			if rec.Code != tc.wantStatus {
				t.Fatalf("%s with scope %q: got %d, want %d (body: %s)",
					tc.path, tc.tokenScope, rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

func TestProtectedRoutesRejectAnonymous(t *testing.T) {
	rs, _ := newTestResourceServer(t)
	mux := rs.routes()

	for _, path := range []string{"/accounts/12345/orders/export", "/orders/12345/fields"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401 without a token, got %d", path, rec.Code)
		}
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	rs, _ := newTestResourceServer(t)
	rec := httptest.NewRecorder()
	rs.routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /healthz, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("unexpected health body: %v", body)
	}
}
