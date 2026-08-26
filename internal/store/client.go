package store

import "time"

const (
	ClientTypePublic       = "public"
	ClientTypeConfidential = "confidential"

	GrantAuthorizationCode   = "authorization_code"
	GrantRefreshToken        = "refresh_token"
	GrantClientCredentials   = "client_credentials"
	GrantTokenExchange       = "token_exchange"
	GrantTokenExchangeURN    = "urn:ietf:params:oauth:grant-type:token-exchange"
	defaultClientStoreDriver = "sqlite"
)

// Client represents an OAuth client registration.
type Client struct {
	ID           string   `json:"client_id"`
	Type         string   `json:"client_type"`
	Secret       string   `json:"client_secret,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
	Audiences    []string `json:"audiences,omitempty"`
	// RFC 7523: JWT Bearer Client Assertions support
	PublicKey    string    `json:"public_key,omitempty"`    // PEM-encoded RSA/ECDSA public key
	KeyAlgorithm string    `json:"key_algorithm,omitempty"` // "RS256", "RS384", "RS512", "ES256", "ES384", "ES512"
	KeyID        string    `json:"key_id,omitempty"`        // Key ID for key rotation
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func NormalizeGrantType(grantType string) string {
	if grantType == GrantTokenExchangeURN {
		return GrantTokenExchange
	}
	return grantType
}

func DefaultClientStoreDriver() string {
	return defaultClientStoreDriver
}
