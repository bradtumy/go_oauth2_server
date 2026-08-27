package auth

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"tokenator/internal/session"
	"tokenator/internal/store"
)

// Permission represents a single permission to display to the user
type Permission struct {
	Name        string
	Description string
}

// ConsentData holds data for the consent page template
type ConsentData struct {
	ClientName          string
	ClientID            string
	UserEmail           string
	Permissions         []Permission
	CSRFToken           string
	RedirectURI         string
	Scope               string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
}

// ScopeDescriptions maps OAuth scopes to user-friendly descriptions
var ScopeDescriptions = map[string]string{
	"openid":         "Verify your identity",
	"profile":        "View your profile information (name, picture)",
	"email":          "View your email address",
	"tickets.read":   "View your support tickets",
	"tickets.write":  "Create and update support tickets",
	"tickets.delete": "Delete support tickets",
	"orders.read":    "View your order history",
	"orders.write":   "Create and modify orders",
	"payments.read":  "View payment information",
	"payments.write": "Process payments",
}

// ConsentRequest carries the authorization request details that must survive the
// consent page and come back with the approval. Grouped into a struct because
// the parameter list had grown past the point where its order was readable.
type ConsentRequest struct {
	Client              store.Client
	Scope               string
	RedirectURI         string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	// Nonce is the OIDC nonce, which must reach the issued ID token.
	Nonce string
}

// ShowConsent displays the OAuth consent page
func (h *Handler) ShowConsent(w http.ResponseWriter, r *http.Request, sess *session.Session, req ConsentRequest) {
	// Parse scopes into permissions
	scopes := strings.Fields(req.Scope)
	permissions := make([]Permission, 0, len(scopes))

	for _, s := range scopes {
		desc, ok := ScopeDescriptions[s]
		if !ok {
			desc = fmt.Sprintf("Access %s", s)
		}
		permissions = append(permissions, Permission{
			Name:        s,
			Description: desc,
		})
	}

	data := ConsentData{
		ClientName:          req.Client.ID,
		ClientID:            req.Client.ID,
		UserEmail:           sess.Email,
		Permissions:         permissions,
		CSRFToken:           sess.CSRFToken,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
	}

	if err := h.templates.ExecuteTemplate(w, "consent.html", data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// RedirectWithError redirects to the client with an OAuth error
func RedirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, errorCode, description, state string) {
	redirect, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "Invalid redirect_uri", http.StatusBadRequest)
		return
	}

	values := redirect.Query()
	values.Set("error", errorCode)
	if description != "" {
		values.Set("error_description", description)
	}
	if state != "" {
		values.Set("state", state)
	}
	redirect.RawQuery = values.Encode()

	http.Redirect(w, r, redirect.String(), http.StatusFound)
}
