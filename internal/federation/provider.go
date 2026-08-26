// Package federation implements the OIDC relying-party half of tokenator: it
// delegates human authentication to an upstream identity provider such as
// Google and returns normalized claims about who signed in.
//
// It knows nothing about tokenator's identity model. Deciding which local
// profile a set of claims corresponds to is the caller's job.
package federation

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrEmailNotVerified is returned when the upstream provider will not vouch for
// the email address it reported. Such claims must not be used to locate or
// create a local profile: an unverified address proves nothing about who
// controls it.
var ErrEmailNotVerified = errors.New("upstream provider did not verify the email address")

// Config describes an upstream OIDC provider.
type Config struct {
	// Issuer is the provider's issuer URL, e.g. https://accounts.google.com.
	// Its discovery document supplies every other endpoint.
	Issuer       string
	ClientID     string
	ClientSecret string
	// RedirectURL must match a redirect URI registered with the provider.
	RedirectURL string
	Scopes      []string
	// DisplayName labels the sign-in button, e.g. "Google".
	DisplayName string
}

// Enabled reports whether enough configuration is present to attempt discovery.
func (c Config) Enabled() bool {
	return strings.TrimSpace(c.Issuer) != "" &&
		strings.TrimSpace(c.ClientID) != "" &&
		strings.TrimSpace(c.ClientSecret) != ""
}

// Claims is the normalized subset of an upstream identity that tokenator uses.
// Raw tokens never escape this package.
type Claims struct {
	// Subject is the provider's stable identifier for this person. It survives
	// email changes, which is why it is the value local profiles are keyed on.
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// Provider is a configured upstream OIDC provider.
type Provider struct {
	cfg      Config
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// New performs OIDC discovery against cfg.Issuer and returns a ready Provider.
//
// Discovery is a network call, so callers must treat failure as "federation
// unavailable" rather than as a fatal startup error: an unreachable provider
// must never prevent the authorization server from serving password logins.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if !cfg.Enabled() {
		return nil, errors.New("federation: issuer, client id and client secret are all required")
	}
	if strings.TrimSpace(cfg.RedirectURL) == "" {
		return nil, errors.New("federation: redirect url is required")
	}

	provider, err := oidc.NewProvider(ctx, strings.TrimSpace(cfg.Issuer))
	if err != nil {
		return nil, fmt.Errorf("federation: discovery against %s: %w", cfg.Issuer, err)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	if !containsFold(scopes, oidc.ScopeOpenID) {
		scopes = append([]string{oidc.ScopeOpenID}, scopes...)
	}

	return &Provider{
		cfg: cfg,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint:     provider.Endpoint(),
			Scopes:       scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// DisplayName is the label for the sign-in button.
func (p *Provider) DisplayName() string {
	if name := strings.TrimSpace(p.cfg.DisplayName); name != "" {
		return name
	}
	return "SSO"
}

// RedirectURL is the callback registered with the provider. Logged at startup
// because a mismatch here is the most common setup failure.
func (p *Provider) RedirectURL() string { return p.oauth.RedirectURL }

// AuthCodeURL builds the URL to send the browser to. The state is echoed back
// on the callback to defeat CSRF; the nonce is embedded in the ID token to
// defeat replay.
func (p *Provider) AuthCodeURL(state, nonce string) string {
	return p.oauth.AuthCodeURL(state, oidc.Nonce(nonce))
}

// Exchange trades an authorization code for an ID token, verifies it, and
// returns normalized claims.
//
// Verification covers the signature, issuer, audience and expiry via go-oidc,
// and this function additionally requires that the nonce matches the one bound
// to the request and that the email is verified.
func (p *Provider) Exchange(ctx context.Context, code, nonce string) (Claims, error) {
	token, err := p.oauth.Exchange(ctx, code)
	if err != nil {
		return Claims{}, fmt.Errorf("federation: exchange authorization code: %w", err)
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return Claims{}, errors.New("federation: token response contained no id_token")
	}

	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return Claims{}, fmt.Errorf("federation: verify id token: %w", err)
	}
	if idToken.Nonce != nonce {
		return Claims{}, errors.New("federation: id token nonce mismatch")
	}

	var raw struct {
		Email         string `json:"email"`
		EmailVerified *bool  `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idToken.Claims(&raw); err != nil {
		return Claims{}, fmt.Errorf("federation: decode id token claims: %w", err)
	}

	claims := Claims{
		Subject:       idToken.Subject,
		Email:         strings.TrimSpace(raw.Email),
		EmailVerified: raw.EmailVerified != nil && *raw.EmailVerified,
		Name:          strings.TrimSpace(raw.Name),
	}
	if claims.Subject == "" {
		return Claims{}, errors.New("federation: id token contained no subject")
	}
	if !claims.EmailVerified {
		return Claims{}, ErrEmailNotVerified
	}
	return claims, nil
}

func containsFold(values []string, want string) bool {
	for _, v := range values {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}
