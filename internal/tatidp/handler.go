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

	"tokenator/internal/identity"
	"tokenator/internal/jwt"
)

// Claim names defined by the relying party's Trusted Auth Token contract. They
// are namespaced URIs rather than bare names, so they are spelled out here once.
const (
	claimDisplayName              = "https://ciam.twilio.com/user_display_name"
	claimScopes                   = "https://ciam.twilio.com/scopes"
	claimAccessTokenClaims        = "https://ciam.twilio.com/access_token_claims"
	claimIDTokenClaims            = "https://ciam.twilio.com/id_token_claims"
	claimUserinfoClaims           = "https://ciam.twilio.com/userinfo_claims"
	claimAuthorizationDetailTypes = "https://ciam.twilio.com/authorization_details_types"
)

// Handler serves the TAT login form and mints tokens against a configured tenant.
type Handler struct {
	Signer *jwt.Signer
	// Issuer identifies this server to the relying party; it must be a URL the
	// relying party can reach.
	Issuer string
	// Audience is the relying party's authorization server, which is not
	// necessarily the host the token is posted to.
	Audience    string
	TenantHost  string
	CallbackURL string
	TokenTTL    time.Duration
	// Scopes is the space-delimited set of scopes an end user may grant, and
	// AuthorizationDetailsTypes the RAR types they may grant.
	Scopes                    string
	AuthorizationDetailsTypes []string
	// Identities, when set, resolves the submitted email to a local profile so
	// the token can carry that profile's attributes. Unknown emails still mint,
	// using the submitted display name and no custom claims.
	Identities identity.Store

	templates *template.Template
}

// kv is an ordered query/form parameter, used to round-trip unknown fields
// (state, request ids, etc.) from the login GET through to the callback POST.
type kv struct {
	Key   string
	Value string
}

// Options configures a TAT handler.
type Options struct {
	Signer                    *jwt.Signer
	Issuer                    string
	Audience                  string
	TenantHost                string
	TokenTTL                  time.Duration
	Scopes                    string
	AuthorizationDetailsTypes []string
	Identities                identity.Store
	// TemplateDir defaults to web/templates relative to the working directory.
	TemplateDir string
}

// NewHandler loads the TAT templates and computes the tenant callback URL.
func NewHandler(opts Options) (*Handler, error) {
	templateDir := opts.TemplateDir
	if templateDir == "" {
		templateDir = filepath.Join("web", "templates")
	}
	tmpl, err := template.ParseFiles(
		filepath.Join(templateDir, "tat_login.html"),
		filepath.Join(templateDir, "tat_callback.html"),
	)
	if err != nil {
		return nil, err
	}

	callbackURL := ""
	if opts.TenantHost != "" {
		callbackURL = "https://" + opts.TenantHost + "/SSO/Callback"
	}
	audience := strings.TrimSpace(opts.Audience)
	if audience == "" && opts.TenantHost != "" {
		audience = "https://" + opts.TenantHost
	}

	return &Handler{
		Signer:                    opts.Signer,
		Issuer:                    opts.Issuer,
		Audience:                  audience,
		TenantHost:                opts.TenantHost,
		CallbackURL:               callbackURL,
		TokenTTL:                  opts.TokenTTL,
		Scopes:                    opts.Scopes,
		AuthorizationDetailsTypes: opts.AuthorizationDetailsTypes,
		Identities:                opts.Identities,
		templates:                 tmpl,
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

	// The relying party supplies a nonce on the login request and requires it
	// back in the token. Minting without one is almost always a misconfigured
	// handshake rather than an intentional call, and the resulting rejection is
	// opaque on the far side, so say so here.
	nonce := r.PostFormValue("nonce")
	if nonce == "" {
		log.Printf("tatidp: WARNING minting a TAT with an empty nonce; the relying party will likely reject it")
	}

	// Resolve the submitted email to a local profile when one exists, so the
	// token carries that profile's stable id and attributes. The relying party
	// keys the end user on sub, so it must not drift between sign-ins.
	subject := email
	customClaims := map[string]any{}
	scopes := h.Scopes
	if h.Identities != nil {
		if human, ok := h.Identities.GetHumanByEmail(r.Context(), email); ok {
			subject = human.ID
			if human.Name != "" {
				name = human.Name
			}
			for k, v := range human.Attributes {
				customClaims[k] = v
			}
			if human.TenantID != "" {
				customClaims["tenant_id"] = human.TenantID
			}
			// A per-profile scopes attribute overrides the server-wide default.
			if perUser, found := human.Attributes["scopes"]; found && strings.TrimSpace(perUser) != "" {
				scopes = perUser
				delete(customClaims, "scopes")
			}
		}
	}
	customClaims["email"] = email

	now := time.Now().UTC()
	claims := jwt.MapClaims{
		"iss":                  h.Issuer,
		"aud":                  h.Audience,
		"sub":                  subject,
		"iat":                  now.Unix(),
		"exp":                  now.Add(h.TokenTTL).Unix(),
		"nonce":                nonce,
		claimDisplayName:       name,
		claimScopes:            scopes,
		claimAccessTokenClaims: customClaims,
		claimIDTokenClaims:     customClaims,
		claimUserinfoClaims:    customClaims,
	}
	// Omit rather than send an empty array, which a relying party may read as
	// "the user may grant nothing" instead of "unspecified".
	if len(h.AuthorizationDetailsTypes) > 0 {
		claims[claimAuthorizationDetailTypes] = h.AuthorizationDetailsTypes
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
