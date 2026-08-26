package auth

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"tokenator/internal/federation"
	"tokenator/internal/identity"
	"tokenator/internal/random"
)

const (
	stateCookieName  = "sso_state"
	nonceCookieName  = "sso_nonce"
	returnCookieName = "sso_return_to"
	// ssoHandshakeTTL bounds how long a sign-in may sit half-finished.
	ssoHandshakeTTL = 10 * time.Minute
)

// FederatedProvider is the upstream OIDC behavior the handlers depend on,
// narrowed to an interface so tests can supply a stub without a network.
type FederatedProvider interface {
	AuthCodeURL(state, nonce string) string
	Exchange(ctx context.Context, code, nonce string) (federation.Claims, error)
	DisplayName() string
}

// SetFederation attaches an upstream provider, enabling the SSO routes and the
// sign-in button. A nil provider leaves federation disabled.
func (h *Handler) SetFederation(p FederatedProvider) { h.federation = p }

// FederationEnabled reports whether an upstream provider is configured.
func (h *Handler) FederationEnabled() bool { return h.federation != nil }

// FederationDisplayName is the sign-in button label, empty when disabled.
func (h *Handler) FederationDisplayName() string {
	if h.federation == nil {
		return ""
	}
	return h.federation.DisplayName()
}

// HandleSSOStart begins an upstream sign-in: it mints single-use state and
// nonce values, remembers them in short-lived cookies, and redirects the
// browser to the provider.
func (h *Handler) HandleSSOStart(w http.ResponseWriter, r *http.Request) {
	if h.federation == nil {
		http.NotFound(w, r)
		return
	}

	state := random.NewID()
	nonce := random.NewID()
	h.setHandshakeCookie(w, stateCookieName, state)
	h.setHandshakeCookie(w, nonceCookieName, nonce)
	// Preserve where the user was headed so the OAuth authorize request they
	// interrupted can resume once they are signed in.
	h.setHandshakeCookie(w, returnCookieName, safeReturnTo(r.URL.Query().Get("return_to")))

	http.Redirect(w, r, h.federation.AuthCodeURL(state, nonce), http.StatusFound)
}

// HandleSSOCallback completes an upstream sign-in, establishing a local session.
func (h *Handler) HandleSSOCallback(w http.ResponseWriter, r *http.Request) {
	if h.federation == nil {
		http.NotFound(w, r)
		return
	}

	query := r.URL.Query()
	returnTo := safeReturnTo(h.handshakeCookie(r, returnCookieName))
	h.clearHandshakeCookies(w)

	// The provider reports user-facing failures (declined consent, for example)
	// in the query string rather than as a transport error.
	if providerErr := strings.TrimSpace(query.Get("error")); providerErr != "" {
		log.Printf("[SSO] provider returned error: %s", providerErr)
		redirectToLoginError(w, r, "Sign-in was not completed")
		return
	}

	// A missing or mismatched state means this callback cannot be tied to a
	// sign-in this browser started, which is what CSRF looks like.
	state := query.Get("state")
	expectedState := h.handshakeCookie(r, stateCookieName)
	if expectedState == "" || state != expectedState {
		log.Printf("[SSO] state mismatch on callback")
		http.Error(w, "Invalid sign-in state", http.StatusBadRequest)
		return
	}

	nonce := h.handshakeCookie(r, nonceCookieName)
	if nonce == "" {
		log.Printf("[SSO] missing nonce on callback")
		http.Error(w, "Invalid sign-in state", http.StatusBadRequest)
		return
	}

	code := query.Get("code")
	if code == "" {
		redirectToLoginError(w, r, "Sign-in was not completed")
		return
	}

	claims, err := h.federation.Exchange(r.Context(), code, nonce)
	if err != nil {
		if errors.Is(err, federation.ErrEmailNotVerified) {
			log.Printf("[SSO] rejected sign-in: email not verified upstream")
			redirectToLoginError(w, r, "Your provider has not verified this email address")
			return
		}
		log.Printf("[SSO] exchange failed: %v", err)
		redirectToLoginError(w, r, "Sign-in failed")
		return
	}

	human, err := ResolveFederatedHuman(r.Context(), h.Identities, "google", claims)
	if err != nil {
		log.Printf("[SSO] identity resolution failed: %v", err)
		redirectToLoginError(w, r, "Sign-in failed")
		return
	}

	sess, err := h.Sessions.Create(human.ID, human.Email)
	if err != nil {
		log.Printf("[SSO] session creation error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	h.setSessionCookie(w, sess.ID)
	log.Printf("[SSO] signed in %s (%s)", human.Email, human.ID)

	http.Redirect(w, r, returnTo, http.StatusFound)
}

// ResolveFederatedHuman maps verified upstream claims onto a local profile.
//
// Resolution is ordered deliberately:
//
//  1. A known upstream subject wins outright. Keying on the subject rather than
//     the email keeps the link intact when someone changes their email upstream.
//  2. Otherwise a verified email may adopt an existing local profile, so a
//     seeded account and its owner's upstream identity converge instead of
//     becoming duplicates.
//  3. Otherwise the profile is created on first sign-in.
//
// Unverified claims never reach step 2 or 3; the provider layer rejects them
// before this point, and this function refuses them again rather than trusting
// its caller, because an unverified address would let anyone claim a profile
// they do not own.
func ResolveFederatedHuman(ctx context.Context, store identity.Store, provider string, claims federation.Claims) (identity.Human, error) {
	if claims.Subject == "" {
		return identity.Human{}, errors.New("upstream claims contained no subject")
	}
	if !claims.EmailVerified {
		return identity.Human{}, federation.ErrEmailNotVerified
	}

	subject := provider + ":" + claims.Subject

	if human, ok := store.GetHumanByFederatedSubject(ctx, subject); ok {
		return human, nil
	}

	if claims.Email != "" {
		if existing, ok := store.GetHumanByEmail(ctx, claims.Email); ok {
			linked, err := store.LinkFederatedSubject(ctx, existing.ID, subject)
			if err != nil {
				return identity.Human{}, err
			}
			return linked, nil
		}
	}

	name := claims.Name
	if name == "" {
		name = claims.Email
	}
	return store.CreateHuman(ctx, identity.Human{
		Email:            claims.Email,
		Name:             name,
		FederatedSubject: subject,
	})
}

// safeReturnTo constrains post-login redirects to paths within this server.
// Without it a crafted sign-in link could bounce a freshly authenticated user
// to an attacker-controlled site, carrying whatever the referrer leaks.
func safeReturnTo(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if candidate == "" {
		return "/"
	}
	// Reject anything absolute or scheme-relative ("//evil.example").
	if strings.HasPrefix(candidate, "//") || strings.Contains(candidate, "://") {
		return "/"
	}
	if !strings.HasPrefix(candidate, "/") {
		return "/"
	}
	parsed, err := url.Parse(candidate)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "/"
	}
	return parsed.RequestURI()
}

func (h *Handler) setHandshakeCookie(w http.ResponseWriter, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ssoHandshakeTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *Handler) handshakeCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

// clearHandshakeCookies expires the handshake values so each is good for a
// single callback.
func (h *Handler) clearHandshakeCookies(w http.ResponseWriter) {
	for _, name := range []string{stateCookieName, nonceCookieName, returnCookieName} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
}

func redirectToLoginError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, "/login?error="+url.QueryEscape(message), http.StatusSeeOther)
}
