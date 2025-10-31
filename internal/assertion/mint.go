package assertion

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	"go_oauth2_server/internal/random"
)

var (
	ErrMissingIssuer   = errors.New("issuer required")
	ErrMissingAudience = errors.New("audience required")
	ErrMissingClientID = errors.New("client id required")
	ErrMissingActorID  = errors.New("actor id required")
	ErrMissingKey      = errors.New("signing key required")
)

// MintOptions defines the parameters for minting a client assertion.
type MintOptions struct {
	Issuer     string
	Audience   string
	ClientID   string
	ActorID    string
	InstanceID string
	SigningKey []byte
	KeyID      string
	TTL        time.Duration
}

// MintClientAssertion generates a signed JWT assertion using the provided options.
func MintClientAssertion(opts MintOptions) (string, error) {
	if len(opts.SigningKey) == 0 {
		return "", ErrMissingKey
	}
	if opts.Issuer == "" {
		return "", ErrMissingIssuer
	}
	if opts.Audience == "" {
		return "", ErrMissingAudience
	}
	if opts.ClientID == "" {
		return "", ErrMissingClientID
	}
	if opts.ActorID == "" {
		return "", ErrMissingActorID
	}
	if opts.InstanceID == "" {
		opts.InstanceID = "run-" + random.NewID()
	}
	if opts.TTL <= 0 {
		opts.TTL = 5 * time.Minute
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss":         opts.Issuer,
		"sub":         opts.ActorID,
		"aud":         opts.Audience,
		"iat":         now.Unix(),
		"exp":         now.Add(opts.TTL).Unix(),
		"jti":         random.NewID(),
		"actor":       opts.ActorID,
		"client_id":   opts.ClientID,
		"instance_id": opts.InstanceID,
	}

	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	if opts.KeyID != "" {
		header["kid"] = opts.KeyID
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, opts.SigningKey)
	if _, err := mac.Write([]byte(unsigned)); err != nil {
		return "", err
	}
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsigned + "." + sig, nil
}
