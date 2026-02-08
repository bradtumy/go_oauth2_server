package jwt

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"time"

	"go_oauth2_server/internal/random"
)

// MapClaims represents JWT claims as a map.
type MapClaims map[string]any

// Signer issues JWTs for both regular access tokens and OBO tokens.
type Signer struct {
	mu          sync.RWMutex
	issuer      string
	audience    string
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	keyID       string
	publicKeys  map[string]*rsa.PublicKey
	privateKeys map[string]*rsa.PrivateKey
	accessTTL   time.Duration
	refreshTTL  time.Duration
	oboTTL      time.Duration
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
func NewSigner(issuer, audience string, keyPEM []byte, keyID string, accessTTL, refreshTTL, oboTTL time.Duration) (*Signer, error) {
	keySet, err := LoadKeySetFromPEM(keyPEM, keyID)
	if err != nil {
		return nil, err
	}
	return NewSignerWithKeySet(issuer, audience, keySet, accessTTL, refreshTTL, oboTTL)
}

// NewSignerWithKeySet constructs a new Signer with a key set.
func NewSignerWithKeySet(issuer, audience string, keySet *KeySet, accessTTL, refreshTTL, oboTTL time.Duration) (*Signer, error) {
	signer := &Signer{
		issuer:     issuer,
		audience:   audience,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
		oboTTL:     oboTTL,
	}
	if err := signer.UpdateKeys(keySet); err != nil {
		return nil, err
	}
	return signer, nil
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
		"alg": "RS256",
		"typ": "JWT",
	}
	keyID, key, err := s.activeKey()
	if err != nil {
		return "", 0, err
	}
	if keyID != "" {
		header["kid"] = keyID
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
	hash := sha256.Sum256([]byte(tokenUnsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", 0, fmt.Errorf("sign token: %w", err)
	}
	return tokenUnsigned + "." + base64.RawURLEncoding.EncodeToString(sig), int(ttl.Seconds()), nil
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
	header, err := parseJWTHeader(parts[0])
	if err != nil {
		return nil, err
	}
	if alg, _ := header["alg"].(string); alg != "RS256" {
		return nil, errors.New("unsupported jwt alg")
	}
	kid, _ := header["kid"].(string)
	publicKey, err := s.publicKeyForKID(kid)
	if err != nil {
		return nil, err
	}
	unsigned := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	hash := sha256.Sum256([]byte(unsigned))
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hash[:], sigBytes); err != nil {
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

// JWKS returns a JWK set exposing the RSA public key.
func (s *Signer) JWKS() (map[string]any, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.publicKeys) == 0 {
		return nil, errors.New("missing signing key")
	}
	keyIDs := make([]string, 0, len(s.publicKeys))
	for keyID := range s.publicKeys {
		keyIDs = append(keyIDs, keyID)
	}
	sort.Strings(keyIDs)
	keys := make([]any, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		publicKey := s.publicKeys[keyID]
		if publicKey == nil {
			continue
		}
		n := base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes())
		jwk := map[string]any{
			"kty": "RSA",
			"alg": "RS256",
			"n":   n,
			"e":   e,
			"kid": keyID,
			"use": "sig",
		}
		keys = append(keys, jwk)
	}
	return map[string]any{"keys": keys}, nil
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

// UpdateKeys swaps the active key set for signing and verification.
func (s *Signer) UpdateKeys(keySet *KeySet) error {
	if keySet == nil || len(keySet.PrivateKeys) == 0 {
		return errors.New("missing signing key set")
	}
	activeKeyID := keySet.ActiveKeyID
	if strings.TrimSpace(activeKeyID) == "" {
		return errors.New("active key id required")
	}
	privateKey, ok := keySet.PrivateKeys[activeKeyID]
	if !ok || privateKey == nil {
		return fmt.Errorf("active signing key %q not found", activeKeyID)
	}
	publicKeys := keySet.PublicKeys
	if len(publicKeys) == 0 {
		publicKeys = map[string]*rsa.PublicKey{}
		for id, key := range keySet.PrivateKeys {
			if key != nil {
				publicKeys[id] = &key.PublicKey
			}
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keyID = activeKeyID
	s.privateKey = privateKey
	s.publicKey = &privateKey.PublicKey
	s.publicKeys = publicKeys
	s.privateKeys = keySet.PrivateKeys
	return nil
}

func (s *Signer) activeKey() (string, *rsa.PrivateKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.privateKey == nil {
		return "", nil, errors.New("missing signing key")
	}
	return s.keyID, s.privateKey, nil
}

func (s *Signer) publicKeyForKID(kid string) (*rsa.PublicKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if kid == "" {
		if s.publicKey == nil {
			return nil, errors.New("missing signing key")
		}
		return s.publicKey, nil
	}
	if s.publicKeys != nil {
		if key, ok := s.publicKeys[kid]; ok && key != nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("unknown kid %q", kid)
}

func parseRSAPrivateKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("invalid PEM")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not RSA private key")
	}
	return key, nil
}

func parseJWTHeader(headerSegment string) (map[string]any, error) {
	headerBytes, err := base64.RawURLEncoding.DecodeString(headerSegment)
	if err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("unmarshal header: %w", err)
	}
	return header, nil
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
