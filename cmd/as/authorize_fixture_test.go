package main

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"tokenator/internal/random"
	"tokenator/internal/store"
)

// testAuthorizeHandler preserves the original handler-level authorization-code
// fixture without adding a bypass to production OAuth code. Authentication and
// consent have their own tests; these tests focus on request validation and the
// downstream authorization-code contract.
func testAuthorizeHandler(s *authorizationServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if !strings.EqualFold(q.Get("response_type"), "code") {
			writeOAuthError(w, http.StatusBadRequest, "unsupported_response_type", "only authorization_code supported")
			return
		}

		clientID := q.Get("client_id")
		client, ok, err := s.clients.GetClient(r.Context(), clientID)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "client lookup failed")
			return
		}
		if !ok {
			writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "unknown client")
			return
		}
		if !clientAllowsGrant(client, store.GrantAuthorizationCode) {
			writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "authorization_code not allowed")
			return
		}

		redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
		if redirectURI == "" {
			if len(client.RedirectURIs) == 1 {
				redirectURI = client.RedirectURIs[0]
			} else {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri required")
				return
			}
		}
		if !redirectURIMatch(client.RedirectURIs, redirectURI) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri mismatch")
			return
		}

		scope := q.Get("scope")
		if scope == "" {
			scope = strings.Join(client.Scopes, " ")
		}
		if !scopeSubsetList(scope, client.Scopes) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "requested scope not allowed")
			return
		}

		challenge := strings.TrimSpace(q.Get("code_challenge"))
		method := strings.ToUpper(strings.TrimSpace(q.Get("code_challenge_method")))
		if challenge != "" && method == "" {
			method = "PLAIN"
		}
		if client.Type == store.ClientTypePublic {
			if challenge == "" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge required for public clients")
				return
			}
			if method != "S256" {
				writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
				return
			}
		} else if challenge != "" && method != "S256" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_challenge_method must be S256")
			return
		}

		human, err := s.lookupHumanByID(r.Context(), q.Get("human_id"))
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "human not found")
			return
		}

		code := random.NewID()
		s.store.SaveCode(store.AuthorizationCode{
			Code:                code,
			ClientID:            clientID,
			HumanID:             human.ID,
			RedirectURI:         redirectURI,
			Scope:               scope,
			CodeChallenge:       challenge,
			CodeChallengeMethod: method,
			IssuedAt:            time.Now().UTC(),
			ExpiresAt:           time.Now().Add(s.cfg.CodeTTL),
		})
		redirect, err := url.Parse(redirectURI)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid redirect_uri")
			return
		}
		values := redirect.Query()
		values.Set("code", code)
		if state := q.Get("state"); state != "" {
			values.Set("state", state)
		}
		redirect.RawQuery = values.Encode()
		http.Redirect(w, r, redirect.String(), http.StatusFound)
	}
}
