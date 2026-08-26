package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"tokenator/internal/federation"
	"tokenator/internal/identity"
	"tokenator/internal/session"
	memstore "tokenator/internal/store/mem"
)

func TestResolveFederatedHumanMatchesKnownSubject(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	created, err := store.CreateHuman(ctx, identity.Human{
		Email:            "dana@example.com",
		Name:             "Dana",
		FederatedSubject: "google:sub-1",
	})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	// A changed upstream email must not create a second profile: the subject is
	// the identifier, the email is only descriptive.
	got, err := ResolveFederatedHuman(ctx, store, "google", federation.Claims{
		Subject:       "sub-1",
		Email:         "dana.new@example.com",
		EmailVerified: true,
		Name:          "Dana",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ID != created.ID {
		t.Fatalf("expected existing human %s, got %s", created.ID, got.ID)
	}

	humans, err := store.ListHumans(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list humans: %v", err)
	}
	if len(humans) != 1 {
		t.Fatalf("expected no new profile, got %d humans", len(humans))
	}
}

func TestResolveFederatedHumanLinksVerifiedEmail(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	seeded, err := store.CreateHuman(ctx, identity.Human{Email: "alice@example.com", Name: "Alice"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	got, err := ResolveFederatedHuman(ctx, store, "google", federation.Claims{
		Subject:       "sub-alice",
		Email:         "alice@example.com",
		EmailVerified: true,
		Name:          "Alice A",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ID != seeded.ID {
		t.Fatalf("expected to adopt seeded profile %s, got %s", seeded.ID, got.ID)
	}
	if got.FederatedSubject != "google:sub-alice" {
		t.Fatalf("expected subject to be linked, got %q", got.FederatedSubject)
	}

	// The link must stick, so a second sign-in resolves by subject.
	again, err := ResolveFederatedHuman(ctx, store, "google", federation.Claims{
		Subject: "sub-alice", Email: "alice@example.com", EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("resolve again: %v", err)
	}
	if again.ID != seeded.ID {
		t.Fatalf("expected stable profile on second sign-in")
	}
}

func TestResolveFederatedHumanCreatesOnFirstSignIn(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()

	got, err := ResolveFederatedHuman(ctx, store, "google", federation.Claims{
		Subject:       "sub-new",
		Email:         "newcomer@example.com",
		EmailVerified: true,
		Name:          "New Comer",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got.ID == "" {
		t.Fatal("expected a created profile")
	}
	if got.Email != "newcomer@example.com" || got.Name != "New Comer" {
		t.Fatalf("unexpected profile: %+v", got)
	}
	if got.FederatedSubject != "google:sub-new" {
		t.Fatalf("expected federated subject to be recorded, got %q", got.FederatedSubject)
	}
	if got.PasswordHash != "" {
		t.Fatal("federated profiles must not be given a password")
	}
}

// TestResolveFederatedHumanRejectsUnverifiedEmail is the account-takeover guard:
// an unverified address proves nothing about who controls it, so it must never
// adopt an existing profile nor create one.
func TestResolveFederatedHumanRejectsUnverifiedEmail(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()
	seeded, err := store.CreateHuman(ctx, identity.Human{Email: "alice@example.com", Name: "Alice"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}

	_, err = ResolveFederatedHuman(ctx, store, "google", federation.Claims{
		Subject:       "sub-attacker",
		Email:         "alice@example.com",
		EmailVerified: false,
		Name:          "Not Alice",
	})
	if !errors.Is(err, federation.ErrEmailNotVerified) {
		t.Fatalf("expected ErrEmailNotVerified, got %v", err)
	}

	reloaded, ok := store.GetHuman(ctx, seeded.ID)
	if !ok {
		t.Fatal("seeded human vanished")
	}
	if reloaded.FederatedSubject != "" {
		t.Fatalf("unverified claims must not link, got %q", reloaded.FederatedSubject)
	}
}

func TestResolveFederatedHumanRequiresSubject(t *testing.T) {
	ctx := context.Background()
	store := memstore.New()

	if _, err := ResolveFederatedHuman(ctx, store, "google", federation.Claims{
		Email: "nobody@example.com", EmailVerified: true,
	}); err == nil {
		t.Fatal("expected an error when claims carry no subject")
	}
}

// TestSafeReturnTo covers the open-redirect guard on post-login redirects.
func TestSafeReturnTo(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"empty defaults to root", "", "/"},
		{"relative path preserved", "/oauth2/authorize?client_id=x", "/oauth2/authorize?client_id=x"},
		{"absolute url rejected", "https://evil.example/steal", "/"},
		{"scheme relative rejected", "//evil.example/steal", "/"},
		{"non rooted path rejected", "evil.example", "/"},
		// Browsers treat a leading backslash as a path separator in some
		// contexts; encoding it keeps the redirect on this origin.
		{"backslash neutralized by encoding", "/\\evil.example", "/%5Cevil.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := safeReturnTo(tc.input); got != tc.want {
				t.Fatalf("safeReturnTo(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// stubProvider stands in for a real upstream so handler behavior can be tested
// without discovery or a network.
type stubProvider struct {
	claims    federation.Claims
	err       error
	lastNonce string
}

func (s *stubProvider) AuthCodeURL(state, nonce string) string {
	return "https://upstream.example/authorize?state=" + state + "&nonce=" + nonce
}

func (s *stubProvider) Exchange(ctx context.Context, code, nonce string) (federation.Claims, error) {
	s.lastNonce = nonce
	if s.err != nil {
		return federation.Claims{}, s.err
	}
	return s.claims, nil
}

func (s *stubProvider) DisplayName() string { return "Fake" }

func newFederatedTestHandler(t *testing.T, provider FederatedProvider) (*Handler, identity.Store) {
	t.Helper()
	idStore := memstore.New()
	h := &Handler{
		Sessions:   session.NewMemoryStore(0),
		Identities: idStore,
	}
	h.SetFederation(provider)
	return h, idStore
}

func TestSSORoutesDisabledWithoutProvider(t *testing.T) {
	h, _ := newFederatedTestHandler(t, nil)
	if h.FederationEnabled() {
		t.Fatal("federation should be disabled with a nil provider")
	}

	for name, handler := range map[string]http.HandlerFunc{
		"start":    h.HandleSSOStart,
		"callback": h.HandleSSOCallback,
	} {
		rec := httptest.NewRecorder()
		handler(rec, httptest.NewRequest(http.MethodGet, "/auth/sso/"+name, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: expected 404 when disabled, got %d", name, rec.Code)
		}
	}
}

func TestSSOStartSetsHandshakeCookies(t *testing.T) {
	h, _ := newFederatedTestHandler(t, &stubProvider{})

	rec := httptest.NewRecorder()
	h.HandleSSOStart(rec, httptest.NewRequest(http.MethodGet, "/auth/sso/login?return_to=/oauth2/authorize%3Fclient_id%3Dx", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	cookies := map[string]string{}
	for _, c := range rec.Result().Cookies() {
		cookies[c.Name] = c.Value
	}
	for _, name := range []string{stateCookieName, nonceCookieName, returnCookieName} {
		if cookies[name] == "" {
			t.Fatalf("expected %s cookie to be set", name)
		}
	}
	if cookies[returnCookieName] != "/oauth2/authorize?client_id=x" {
		t.Fatalf("unexpected return_to cookie %q", cookies[returnCookieName])
	}
	if !strings.Contains(rec.Header().Get("Location"), cookies[stateCookieName]) {
		t.Fatal("redirect should carry the state that was stored")
	}
}

// TestSSOStartRejectsExternalReturnTo keeps a crafted sign-in link from turning
// the callback into an open redirect.
func TestSSOStartRejectsExternalReturnTo(t *testing.T) {
	h, _ := newFederatedTestHandler(t, &stubProvider{})

	rec := httptest.NewRecorder()
	h.HandleSSOStart(rec, httptest.NewRequest(http.MethodGet, "/auth/sso/login?return_to=https://evil.example/steal", nil))

	for _, c := range rec.Result().Cookies() {
		if c.Name == returnCookieName && c.Value != "/" {
			t.Fatalf("expected external return_to to be discarded, got %q", c.Value)
		}
	}
}

func TestSSOCallbackRejectsStateMismatch(t *testing.T) {
	h, _ := newFederatedTestHandler(t, &stubProvider{})

	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=c&state=attacker", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "genuine"})
	req.AddCookie(&http.Cookie{Name: nonceCookieName, Value: "n"})
	rec := httptest.NewRecorder()
	h.HandleSSOCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 on state mismatch, got %d", rec.Code)
	}
}

func TestSSOCallbackRequiresNonceCookie(t *testing.T) {
	h, _ := newFederatedTestHandler(t, &stubProvider{})

	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=c&state=s", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "s"})
	rec := httptest.NewRecorder()
	h.HandleSSOCallback(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 without a nonce, got %d", rec.Code)
	}
}

func TestSSOCallbackSignsInAndRedirects(t *testing.T) {
	provider := &stubProvider{claims: federation.Claims{
		Subject:       "sub-42",
		Email:         "sso@example.com",
		EmailVerified: true,
		Name:          "SSO User",
	}}
	h, idStore := newFederatedTestHandler(t, provider)

	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=c&state=s", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "s"})
	req.AddCookie(&http.Cookie{Name: nonceCookieName, Value: "the-nonce"})
	req.AddCookie(&http.Cookie{Name: returnCookieName, Value: "/oauth2/authorize?client_id=x"})
	rec := httptest.NewRecorder()
	h.HandleSSOCallback(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d (%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/oauth2/authorize?client_id=x" {
		t.Fatalf("expected to resume the interrupted request, got %q", got)
	}
	// The nonce from the cookie must reach the provider, or replay protection
	// is decorative.
	if provider.lastNonce != "the-nonce" {
		t.Fatalf("expected nonce to be passed to Exchange, got %q", provider.lastNonce)
	}

	var sessionID string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "session_id" {
			sessionID = c.Value
		}
	}
	if sessionID == "" {
		t.Fatal("expected a session cookie")
	}
	sess, err := h.Sessions.Get(sessionID)
	if err != nil {
		t.Fatalf("session not stored: %v", err)
	}

	human, ok := idStore.GetHumanByFederatedSubject(context.Background(), "google:sub-42")
	if !ok {
		t.Fatal("expected a profile to be created for the upstream subject")
	}
	if sess.HumanID != human.ID {
		t.Fatalf("session bound to %q, expected %q", sess.HumanID, human.ID)
	}
}

func TestSSOCallbackSurfacesUnverifiedEmail(t *testing.T) {
	h, _ := newFederatedTestHandler(t, &stubProvider{err: federation.ErrEmailNotVerified})

	req := httptest.NewRequest(http.MethodGet, "/auth/sso/callback?code=c&state=s", nil)
	req.AddCookie(&http.Cookie{Name: stateCookieName, Value: "s"})
	req.AddCookie(&http.Cookie{Name: nonceCookieName, Value: "n"})
	rec := httptest.NewRecorder()
	h.HandleSSOCallback(rec, req)

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected a redirect back to login, got %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "verified") {
		t.Fatalf("expected an explanatory error, got %q", loc)
	}
}
