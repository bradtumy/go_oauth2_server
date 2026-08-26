package federation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeIssuer is a minimal OIDC provider: it serves a discovery document and a
// JWKS, and mints ID tokens signed with its own key. Exercising the real
// verification path against it keeps these tests honest without reaching the
// network or needing a Google account.
type fakeIssuer struct {
	server   *httptest.Server
	key      *rsa.PrivateKey
	clientID string

	// knobs the tests use to produce bad tokens
	subject       string
	email         string
	emailVerified bool
	name          string
	nonce         string
	audience      string
	issuer        string
	expiry        time.Time
}

func newFakeIssuer(t *testing.T, clientID string) *fakeIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	fi := &fakeIssuer{
		key:           key,
		clientID:      clientID,
		subject:       "upstream-subject-1",
		email:         "person@example.com",
		emailVerified: true,
		name:          "Test Person",
		expiry:        time.Now().Add(5 * time.Minute),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                                fi.issuerURL(),
			"authorization_endpoint":                fi.issuerURL() + "/authorize",
			"token_endpoint":                        fi.issuerURL() + "/token",
			"jwks_uri":                              fi.issuerURL() + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := fi.key.Public().(*rsa.PublicKey)
		writeJSON(w, map[string]any{"keys": []any{map[string]any{
			"kty": "RSA",
			"alg": "RS256",
			"use": "sig",
			"kid": "fake-key",
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]any{
			"access_token": "fake-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     fi.mintIDToken(t),
		})
	})

	fi.server = httptest.NewServer(mux)
	t.Cleanup(fi.server.Close)
	return fi
}

func (fi *fakeIssuer) issuerURL() string {
	if fi.issuer != "" {
		return fi.issuer
	}
	return fi.server.URL
}

func (fi *fakeIssuer) mintIDToken(t *testing.T) string {
	t.Helper()
	aud := fi.audience
	if aud == "" {
		aud = fi.clientID
	}
	claims := jwt.MapClaims{
		"iss":            fi.issuerURL(),
		"aud":            aud,
		"sub":            fi.subject,
		"exp":            fi.expiry.Unix(),
		"iat":            time.Now().Unix(),
		"email":          fi.email,
		"email_verified": fi.emailVerified,
		"name":           fi.name,
	}
	if fi.nonce != "" {
		claims["nonce"] = fi.nonce
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "fake-key"
	signed, err := token.SignedString(fi.key)
	if err != nil {
		t.Fatalf("sign id token: %v", err)
	}
	return signed
}

func (fi *fakeIssuer) provider(t *testing.T) *Provider {
	t.Helper()
	p, err := New(context.Background(), Config{
		Issuer:       fi.server.URL,
		ClientID:     fi.clientID,
		ClientSecret: "fake-secret",
		RedirectURL:  "http://localhost:8080/auth/sso/callback",
		DisplayName:  "Fake",
	})
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	return p
}

func writeJSON(w http.ResponseWriter, payload any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func TestExchangeReturnsVerifiedClaims(t *testing.T) {
	fi := newFakeIssuer(t, "test-client")
	fi.nonce = "nonce-abc"
	p := fi.provider(t)

	claims, err := p.Exchange(context.Background(), "any-code", "nonce-abc")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if claims.Subject != "upstream-subject-1" {
		t.Fatalf("unexpected subject %q", claims.Subject)
	}
	if claims.Email != "person@example.com" || !claims.EmailVerified {
		t.Fatalf("unexpected email claims: %+v", claims)
	}
	if claims.Name != "Test Person" {
		t.Fatalf("unexpected name %q", claims.Name)
	}
}

// TestExchangeRejectsNonceMismatch covers replay: a token minted for one
// sign-in must not be usable against a different one.
func TestExchangeRejectsNonceMismatch(t *testing.T) {
	fi := newFakeIssuer(t, "test-client")
	fi.nonce = "nonce-from-another-request"
	p := fi.provider(t)

	if _, err := p.Exchange(context.Background(), "any-code", "nonce-we-expected"); err == nil {
		t.Fatal("expected nonce mismatch to fail")
	}
}

func TestExchangeRejectsUnverifiedEmail(t *testing.T) {
	fi := newFakeIssuer(t, "test-client")
	fi.nonce = "n"
	fi.emailVerified = false
	p := fi.provider(t)

	_, err := p.Exchange(context.Background(), "any-code", "n")
	if !errors.Is(err, ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}
}

func TestExchangeRejectsWrongAudience(t *testing.T) {
	fi := newFakeIssuer(t, "test-client")
	fi.nonce = "n"
	fi.audience = "some-other-client"
	p := fi.provider(t)

	if _, err := p.Exchange(context.Background(), "any-code", "n"); err == nil {
		t.Fatal("expected audience mismatch to fail")
	}
}

func TestExchangeRejectsExpiredToken(t *testing.T) {
	fi := newFakeIssuer(t, "test-client")
	fi.nonce = "n"
	fi.expiry = time.Now().Add(-time.Hour)
	p := fi.provider(t)

	if _, err := p.Exchange(context.Background(), "any-code", "n"); err == nil {
		t.Fatal("expected expired id token to fail")
	}
}

func TestAuthCodeURLCarriesStateAndNonce(t *testing.T) {
	fi := newFakeIssuer(t, "test-client")
	p := fi.provider(t)

	raw := p.AuthCodeURL("state-xyz", "nonce-xyz")
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse auth url: %v", err)
	}
	q := parsed.Query()
	if q.Get("state") != "state-xyz" {
		t.Fatalf("missing state, got %q", q.Get("state"))
	}
	if q.Get("nonce") != "nonce-xyz" {
		t.Fatalf("missing nonce, got %q", q.Get("nonce"))
	}
	if q.Get("client_id") != "test-client" {
		t.Fatalf("unexpected client_id %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "http://localhost:8080/auth/sso/callback" {
		t.Fatalf("unexpected redirect_uri %q", q.Get("redirect_uri"))
	}
}

func TestConfigEnabledRequiresAllCredentials(t *testing.T) {
	cases := []struct {
		name string
		cfg  Config
		want bool
	}{
		{"complete", Config{Issuer: "https://i", ClientID: "c", ClientSecret: "s"}, true},
		{"no issuer", Config{ClientID: "c", ClientSecret: "s"}, false},
		{"no client id", Config{Issuer: "https://i", ClientSecret: "s"}, false},
		{"no secret", Config{Issuer: "https://i", ClientID: "c"}, false},
		{"empty", Config{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.Enabled(); got != tc.want {
				t.Fatalf("Enabled() = %v, want %v", got, tc.want)
			}
		})
	}
}
