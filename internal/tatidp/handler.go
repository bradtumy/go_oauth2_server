// Package tatidp is a minimal stand-in for the "HelloIDP" local identity
// provider used in the M1 Agent Identity bug bash: it serves a name/email
// login form and mints a signed Trusted Auth Token (TAT) that auto-POSTs to
// a configured tenant's /SSO/Callback endpoint.
package tatidp

import (
	"html/template"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"tokenator/internal/jwt"
)

// Handler serves the TAT login form and mints tokens against a configured tenant.
type Handler struct {
	Signer      *jwt.Signer
	Issuer      string
	TenantHost  string
	CallbackURL string
	TokenTTL    time.Duration

	templates *template.Template
}

// kv is an ordered query/form parameter, used to round-trip unknown fields
// (state, request ids, etc.) from the login GET through to the callback POST.
type kv struct {
	Key   string
	Value string
}

// NewHandler loads the TAT templates and computes the tenant callback URL,
// resolving templates relative to the process working directory.
func NewHandler(signer *jwt.Signer, issuer, tenantHost string, tokenTTL time.Duration) (*Handler, error) {
	return NewHandlerWithTemplates(signer, issuer, tenantHost, tokenTTL, filepath.Join("web", "templates"))
}

// NewHandlerWithTemplates is NewHandler with an explicit template directory, for
// callers that do not run from the repository root (tests, alternate layouts).
func NewHandlerWithTemplates(signer *jwt.Signer, issuer, tenantHost string, tokenTTL time.Duration, templateDir string) (*Handler, error) {
	tmpl, err := template.ParseFiles(
		filepath.Join(templateDir, "tat_login.html"),
		filepath.Join(templateDir, "tat_callback.html"),
	)
	if err != nil {
		return nil, err
	}
	callbackURL := ""
	if tenantHost != "" {
		callbackURL = "https://" + tenantHost + "/SSO/Callback"
	}
	return &Handler{
		Signer:      signer,
		Issuer:      issuer,
		TenantHost:  tenantHost,
		CallbackURL: callbackURL,
		TokenTTL:    tokenTTL,
		templates:   tmpl,
	}, nil
}

// ShowLogin renders the name/email login form.
func (h *Handler) ShowLogin(w http.ResponseWriter, r *http.Request) {
	if h.TenantHost == "" {
		http.Error(w, "TAT_TENANT_HOST is not configured", http.StatusPreconditionFailed)
		return
	}
	data := map[string]any{
		"CallbackURL": h.CallbackURL,
		"Passthrough": passthroughParams(r.URL.Query()),
	}
	if err := h.templates.ExecuteTemplate(w, "tat_login.html", data); err != nil {
		log.Printf("tatidp: template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleLogin mints a TAT for the submitted name/email and renders a page
// that auto-POSTs it to the configured tenant's /SSO/Callback.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if h.TenantHost == "" {
		http.Error(w, "TAT_TENANT_HOST is not configured", http.StatusPreconditionFailed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(r.PostFormValue("name"))
	email := strings.TrimSpace(r.PostFormValue("email"))
	if name == "" || email == "" {
		http.Error(w, "name and email are required", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":   h.Issuer,
		"aud":   "https://" + h.TenantHost,
		"sub":   email,
		"email": email,
		"name":  name,
		"iat":   now.Unix(),
		"exp":   now.Add(h.TokenTTL).Unix(),
	}
	if nonce := r.PostFormValue("nonce"); nonce != "" {
		claims["nonce"] = nonce
	}

	token, err := h.Signer.IssueRaw(claims)
	if err != nil {
		log.Printf("tatidp: sign error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	data := map[string]any{
		"CallbackURL": h.CallbackURL,
		"Token":       token,
		"Passthrough": passthroughParams(r.Form),
	}
	if err := h.templates.ExecuteTemplate(w, "tat_callback.html", data); err != nil {
		log.Printf("tatidp: template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// PublicKeyPEM serves the signer's RSA public key for upload into the
// tenant's Trusted Auth Token "Public Keys" section.
func (h *Handler) PublicKeyPEM(w http.ResponseWriter, r *http.Request) {
	pemStr, err := h.Signer.PublicKeyPEM()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write([]byte(pemStr))
}

// passthroughParams collects params other than the known login fields, so
// any tenant round-trip values (state, nonce already handled separately,
// request ids, etc.) survive the login -> callback hop without needing to
// know their exact names ahead of time.
func passthroughParams(values url.Values) []kv {
	skip := map[string]bool{"name": true, "email": true, "nonce": true}
	keys := make([]string, 0, len(values))
	for k := range values {
		if skip[k] {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]kv, 0, len(keys))
	for _, k := range keys {
		out = append(out, kv{Key: k, Value: values.Get(k)})
	}
	return out
}
