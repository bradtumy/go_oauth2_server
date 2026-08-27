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

	"tokenator/internal/random"
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
	return s.issue(ctx, subject, clientID, scope, nil, nil, s.accessTTL, s.audience, extra, "")
}

// IssueAccessWithDPoP issues a DPoP-bound access token (RFC 9449).
// The dpopJKT parameter is the JWK thumbprint that binds the token to a specific DPoP key.
func (s *Signer) IssueAccessWithDPoP(ctx context.Context, subject, clientID, scope string, dpopJKT string, extra map[string]any) (string, int, error) {
	return s.issue(ctx, subject, clientID, scope, nil, nil, s.accessTTL, s.audience, extra, dpopJKT)
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
	// Standard OAuth 2.0: convert perms array to space-separated scope string
	scope := strings.Join(perms, " ")
	return s.issue(ctx, subject, clientID, scope, perms, authz, ttl, audience, extraMap, "")
}

// IDTokenRequest describes an OpenID Connect ID token to issue.
type IDTokenRequest struct {
	// Subject is the end user's stable identifier, becoming the sub claim.
	Subject string
	// ClientID becomes the audience: an ID token is issued *to* the client,
	// unlike an access token, which is issued for a resource server.
	ClientID string
	// Nonce, when the client sent one, is echoed so the client can tie the
	// token to its own authorization request.
	Nonce string
	// AccessToken, when present, produces an at_hash claim binding the two
	// tokens together (OpenID Connect Core 3.1.3.6).
	AccessToken string
	// Claims are the identity claims released for the granted scopes.
	Claims map[string]any
	TTL    time.Duration
}

// IssueIDToken issues an OpenID Connect ID token.
//
// An ID token asserts who authenticated to the client, so its audience is the
// client rather than a resource server, and it must not be used as a bearer
// credential against an API.
func (s *Signer) IssueIDToken(req IDTokenRequest) (string, error) {
	if strings.TrimSpace(req.Subject) == "" {
		return "", errors.New("id token requires a subject")
	}
	if strings.TrimSpace(req.ClientID) == "" {
		return "", errors.New("id token requires a client id")
	}
	ttl := req.TTL
	if ttl <= 0 {
		ttl = s.accessTTL
	}
	if ttl <= 0 {
		ttl = time.Hour
	}

	now := time.Now().UTC()
	claims := MapClaims{
		"iss":       s.issuer,
		"sub":       req.Subject,
		"aud":       req.ClientID,
		"iat":       now.Unix(),
		"nbf":       now.Unix(),
		"exp":       now.Add(ttl).Unix(),
		"jti":       random.NewID(),
		"auth_time": now.Unix(),
	}
	for k, v := range req.Claims {
		// Never let released claims overwrite the token's own identity.
		switch k {
		case "iss", "sub", "aud", "iat", "nbf", "exp", "jti", "nonce", "at_hash":
			continue
		}
		claims[k] = v
	}
	if req.Nonce != "" {
		claims["nonce"] = req.Nonce
	}
	if req.AccessToken != "" {
		claims["at_hash"] = AtHash(req.AccessToken)
	}

	return s.IssueRaw(claims)
}

// AtHash computes the OpenID Connect at_hash: the left-most half of the
// SHA-256 of the access token's ASCII representation, base64url encoded.
func AtHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// IssueSubjectAssertion issues a subject assertion JWT for token exchange bootstrap.
func (s *Signer) IssueSubjectAssertion(ctx context.Context, subject string, ttl time.Duration) (string, int, error) {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	extra := map[string]any{
		"token_use": "subject_assertion",
	}
	// For educational OAuth 2.0 demonstration: grant humans broad scope set
	// In production, this should come from user entitlements/roles database
	defaultHumanScopes := "tickets.read tickets.write orders.read orders.write"
	return s.issue(ctx, subject, subject, defaultHumanScopes, nil, nil, ttl, s.issuer, extra, "")
}

func (s *Signer) issue(ctx context.Context, subject, clientID, scope string, perms []string, authz any, ttl time.Duration, audience string, extra map[string]any, dpopJKT string) (token string, expiresIn int, err error) {
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
	// Note: perms parameter is deprecated - use authorization_details (RFC 9396) instead
	// The perm claim was non-standard and has been removed for standards compliance
	if authz != nil {
		claims["authorization_details"] = authz
	}
	// RFC 9449: Add cnf (confirmation) claim for DPoP-bound tokens
	if dpopJKT != "" {
		claims["cnf"] = map[string]any{
			"jkt": dpopJKT,
		}
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

// IssueRaw signs an arbitrary claims map as-is, filling in iat/jti only if absent.
// Unlike issue(), it does not force iss/aud to the Signer's configured values —
// used for minting tokens on behalf of a foreign issuer/audience pair (e.g.
// emulating an external Trusted Auth Token IdP against a third-party tenant).
func (s *Signer) IssueRaw(claims MapClaims) (string, error) {
	now := time.Now().UTC()
	out := make(MapClaims, len(claims))
	for k, v := range claims {
		out[k] = v
	}
	if _, ok := out["iat"]; !ok {
		out["iat"] = now.Unix()
	}
	if _, ok := out["jti"]; !ok {
		out["jti"] = random.NewID()
	}

	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
	}
	keyID, key, err := s.activeKey()
	if err != nil {
		return "", err
	}
	if keyID != "" {
		header["kid"] = keyID
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	claimsJSON, err := json.Marshal(out)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	tokenUnsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	hash := sha256.Sum256([]byte(tokenUnsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return tokenUnsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// PublicKeyPEM returns the active RSA public key, PEM-encoded (SubjectPublicKeyInfo),
// for out-of-band distribution to relying parties that expect an uploaded key file
// rather than JWKS (e.g. a staging tenant's Trusted Auth Token "Public Keys" section).
func (s *Signer) PublicKeyPEM() (string, error) {
	s.mu.RLock()
	pub := s.publicKey
	s.mu.RUnlock()
	if pub == nil {
		return "", errors.New("missing signing key")
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("marshal public key: %w", err)
	}
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), nil
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
