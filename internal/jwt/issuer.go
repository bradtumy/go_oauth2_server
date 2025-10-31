package jwt

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"go_oauth2_server/internal/random"
)

// MapClaims represents JWT claims as a map.
type MapClaims map[string]any

// Signer issues JWTs for both regular access tokens and OBO tokens.
type Signer struct {
	issuer     string
	audience   string
	key        []byte
	keyID      string
	accessTTL  time.Duration
	refreshTTL time.Duration
	oboTTL     time.Duration
}

var (
	// ErrAudienceMismatch indicates the provided audience claim does not match the expected value.
	ErrAudienceMismatch = errors.New("audience mismatch")
	// ErrIssuerMismatch indicates the issuer claim is unexpected.
	ErrIssuerMismatch = errors.New("issuer mismatch")
	// ErrTokenExpired indicates the token is no longer valid based on exp.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenNotYetValid indicates the token is not valid yet due to nbf.
	ErrTokenNotYetValid = errors.New("token not yet valid")
)

// NewSigner constructs a new Signer instance.
func NewSigner(issuer, audience string, key []byte, keyID string, accessTTL, refreshTTL, oboTTL time.Duration) *Signer {
	return &Signer{
		issuer:     issuer,
		audience:   audience,
		key:        key,
		keyID:      keyID,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		oboTTL:     oboTTL,
	}
}

// IssueAccess issues a standard access token for a subject and client.
func (s *Signer) IssueAccess(ctx context.Context, subject, clientID, scope string) (token string, expiresIn int, err error) {
        return s.IssueAccessWithClaims(ctx, subject, clientID, scope, nil)
}

// IssueAccessWithClaims issues an access token with additional private claims.
func (s *Signer) IssueAccessWithClaims(ctx context.Context, subject, clientID, scope string, extra map[string]any) (string, int, error) {
        return s.issue(ctx, subject, clientID, scope, nil, nil, s.accessTTL, s.audience, extra)
}

// IssueOBOToken issues an OBO access token with given claims payload.
func (s *Signer) IssueOBOToken(ctx context.Context, subject, clientID string, perms []string, authz any, actor any, ttl time.Duration, extra map[string]any, audience string) (token string, expiresIn int, err error) {
	if ttl <= 0 {
		ttl = s.oboTTL
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	if audience == "" {
		audience = s.audience
	}
	extraMap := map[string]any{}
	for k, v := range extra {
		extraMap[k] = v
	}
	if actor != nil {
		extraMap["act"] = actor
	}
        return s.issue(ctx, subject, clientID, "", perms, authz, ttl, audience, extraMap)
}

// IssueSubjectAssertion issues a subject assertion JWT for token exchange bootstrap.
func (s *Signer) IssueSubjectAssertion(ctx context.Context, subject string, ttl time.Duration) (string, int, error) {
        if ttl <= 0 {
                ttl = 5 * time.Minute
        }
        extra := map[string]any{
                "token_use": "subject_assertion",
        }
        return s.issue(ctx, subject, subject, "", nil, nil, ttl, s.issuer, extra)
}

func (s *Signer) issue(ctx context.Context, subject, clientID, scope string, perms []string, authz any, ttl time.Duration, audience string, extra map[string]any) (token string, expiresIn int, err error) {
	now := time.Now().UTC()
	expires := now.Add(ttl)
	claims := MapClaims{
		"iss":       s.issuer,
		"aud":       audience,
		"sub":       subject,
		"client_id": clientID,
		"iat":       now.Unix(),
		"exp":       expires.Unix(),
		"nbf":       now.Unix(),
		"jti":       random.NewID(),
	}
	if scope != "" {
		claims["scope"] = scope
	}
	if len(perms) > 0 {
		claims["perm"] = perms
	}
	if authz != nil {
		claims["authorization_details"] = authz
	}
	for k, v := range extra {
		if v == nil {
			continue
		}
		claims[k] = v
	}

	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", 0, fmt.Errorf("marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", 0, fmt.Errorf("marshal claims: %w", err)
	}
	tokenUnsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(tokenUnsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return tokenUnsigned + "." + sig, int(ttl.Seconds()), nil
}

// Verify validates a JWT and returns map claims.
func (s *Signer) Verify(token, expectedAudience string) (MapClaims, error) {
	aud := expectedAudience
	if aud == "" {
		aud = s.audience
	}
	parts := stringsSplit(token, '.')
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}
	unsigned := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(unsigned))
	if !hmac.Equal(sigBytes, mac.Sum(nil)) {
		return nil, errors.New("signature mismatch")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims MapClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal claims: %w", err)
	}
	if iss, ok := claims["iss"].(string); !ok || iss != s.issuer {
		return nil, ErrIssuerMismatch
	}
	if !validateAudience(claims["aud"], aud) {
		return nil, ErrAudienceMismatch
	}
	if err := validateTimes(claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func validateAudience(value any, expected string) bool {
	switch v := value.(type) {
	case string:
		return v == expected
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok && s == expected {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if item == expected {
				return true
			}
		}
	}
	return false
}

func validateTimes(claims MapClaims) error {
	now := time.Now().Unix()
	if exp, ok := asInt(claims["exp"]); ok && now > exp {
		return ErrTokenExpired
	}
	if nbf, ok := asInt(claims["nbf"]); ok && now < nbf {
		return ErrTokenNotYetValid
	}
	return nil
}

func asInt(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		return int64(t), true
	case float32:
		return int64(t), true
	case int64:
		return t, true
	case int:
		return int64(t), true
	case json.Number:
		i, err := t.Int64()
		if err != nil {
			return 0, false
		}
		return i, true
	}
	return 0, false
}

// JWKS returns a simple JWK set exposing the symmetric key for development.
func (s *Signer) JWKS() (map[string]any, error) {
	if len(s.key) == 0 {
		return nil, errors.New("missing signing key")
	}
	k := base64.RawURLEncoding.EncodeToString(s.key)
	jwk := map[string]any{
		"kty": "oct",
		"alg": "HS256",
		"k":   k,
		"kid": s.keyID,
		"use": "sig",
	}
	return map[string]any{"keys": []any{jwk}}, nil
}

// ComputeSubjectHash returns a stable hash for subject entitlements.
func ComputeSubjectHash(subject string, perms []string) string {
	h := hmac.New(sha256.New, []byte(subject))
	payload, _ := json.Marshal(perms)
	h.Write(payload)
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// Audience exposes the configured default audience.
func (s *Signer) Audience() string {
	return s.audience
}

// Issuer exposes the configured issuer.
func (s *Signer) Issuer() string {
	return s.issuer
}

func stringsSplit(s string, sep rune) []string {
	var parts []string
	start := 0
	for i, r := range s {
		if r == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}
