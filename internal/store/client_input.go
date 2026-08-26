package store

import (
	"errors"
	"fmt"
	"strings"
)

var (
	ErrClientNotFound = errors.New("client not found")
	ErrClientExists   = errors.New("client already exists")
)

type ClientInput struct {
	ClientID     string   `json:"client_id"`
	ClientType   string   `json:"client_type"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`
	Scopes       []string `json:"scopes"`
	Audiences    []string `json:"audiences"`
	// RFC 7523: JWT Bearer Client Assertions support
	PublicKey    string `json:"public_key"`
	KeyAlgorithm string `json:"key_algorithm"`
	KeyID        string `json:"key_id"`
}

func ValidateClientInput(input ClientInput) (ClientInput, error) {
	input.ClientID = strings.TrimSpace(input.ClientID)
	if input.ClientID == "" {
		return ClientInput{}, errors.New("client_id required")
	}
	input.ClientType = strings.ToLower(strings.TrimSpace(input.ClientType))
	switch input.ClientType {
	case ClientTypePublic, ClientTypeConfidential:
	default:
		return ClientInput{}, errors.New("client_type must be public or confidential")
	}
	input.ClientSecret = strings.TrimSpace(input.ClientSecret)
	input.PublicKey = strings.TrimSpace(input.PublicKey)
	input.KeyAlgorithm = strings.TrimSpace(input.KeyAlgorithm)
	input.KeyID = strings.TrimSpace(input.KeyID)

	// RFC 7523: Confidential clients can use either client_secret OR public_key (not both required)
	if input.ClientType == ClientTypeConfidential {
		hasSecret := input.ClientSecret != ""
		hasPublicKey := input.PublicKey != ""

		if !hasSecret && !hasPublicKey {
			return ClientInput{}, errors.New("confidential clients require either client_secret or public_key")
		}

		// If public key provided, validate it
		if hasPublicKey {
			if input.KeyAlgorithm == "" {
				return ClientInput{}, errors.New("key_algorithm required when public_key is provided")
			}
			if !validKeyAlgorithm(input.KeyAlgorithm) {
				return ClientInput{}, fmt.Errorf("unsupported key_algorithm %q (supported: RS256, RS384, RS512, ES256, ES384, ES512)", input.KeyAlgorithm)
			}
		}
	}
	if input.ClientType == ClientTypePublic {
		input.ClientSecret = ""
		input.PublicKey = ""
		input.KeyAlgorithm = ""
		input.KeyID = ""
	}
	input.RedirectURIs = normalizeList(input.RedirectURIs)
	rawGrants := normalizeList(input.GrantTypes)
	input.GrantTypes = make([]string, 0, len(rawGrants))
	for _, grant := range rawGrants {
		if NormalizeGrantType(grant) != grant {
			grant = NormalizeGrantType(grant)
		}
		input.GrantTypes = append(input.GrantTypes, grant)
	}
	input.Scopes = normalizeList(input.Scopes)
	input.Audiences = normalizeList(input.Audiences)
	if len(input.GrantTypes) == 0 {
		return ClientInput{}, errors.New("grant_types required")
	}
	for _, grant := range input.GrantTypes {
		if !validGrantType(grant) {
			return ClientInput{}, fmt.Errorf("unsupported grant_type %q", grant)
		}
	}
	if contains(input.GrantTypes, GrantAuthorizationCode) && len(input.RedirectURIs) == 0 {
		return ClientInput{}, errors.New("redirect_uris required for authorization_code")
	}
	return input, nil
}

func validGrantType(grant string) bool {
	switch grant {
	case GrantAuthorizationCode, GrantRefreshToken, GrantClientCredentials, GrantTokenExchange:
		return true
	default:
		return false
	}
}

func validKeyAlgorithm(alg string) bool {
	switch alg {
	case "RS256", "RS384", "RS512", "ES256", "ES384", "ES512":
		return true
	default:
		return false
	}
}

func normalizeList(values []string) []string {
	unique := make(map[string]struct{})
	var normalized []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := unique[value]; ok {
			continue
		}
		unique[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func contains(list []string, value string) bool {
	for _, entry := range list {
		if entry == value {
			return true
		}
	}
	return false
}
