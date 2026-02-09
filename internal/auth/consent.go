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

// ShowConsent displays the OAuth consent page
func (h *Handler) ShowConsent(w http.ResponseWriter, r *http.Request, sess *session.Session, client store.Client, scope, redirectURI, state, codeChallenge, codeChallengeMethod string) {
	// Parse scopes into permissions
	scopes := strings.Fields(scope)
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
		ClientName:          client.ID,
		ClientID:            client.ID,
		UserEmail:           sess.Email,
		Permissions:         permissions,
		CSRFToken:           sess.CSRFToken,
		RedirectURI:         redirectURI,
		Scope:               scope,
		State:               state,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
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
