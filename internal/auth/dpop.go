package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"tokenator/internal/store"
)

var (
	ErrInvalidDPoPProof   = errors.New("invalid DPoP proof")
	ErrDPoPReplayDetected = errors.New("DPoP proof replay detected")
	ErrDPoPMethodMismatch = errors.New("DPoP htm claim mismatch")
	ErrDPoPURLMismatch    = errors.New("DPoP htu claim mismatch")
	ErrDPoPTypMissing     = errors.New("DPoP typ header must be dpop+jwt")
	ErrDPoPJWKMissing     = errors.New("DPoP jwk header required")
	ErrDPoPStaleProof     = errors.New("DPoP proof timestamp too old")
)

// DPoPClaims represents the claims in a DPoP proof JWT (RFC 9449).
type DPoPClaims struct {
	JTI string `json:"jti"` // Unique identifier (required)
	HTM string `json:"htm"` // HTTP method (required)
	HTU string `json:"htu"` // HTTP URL without query/fragment (required)
	IAT int64  `json:"iat"` // Issued at timestamp (required)
	ATH string `json:"ath,omitempty"` // Access token hash (for resource server requests)
	jwt.RegisteredClaims
}

// DPoPHeader represents the JWT header for a DPoP proof.
type DPoPHeader struct {
	Type      string         `json:"typ"` // Must be "dpop+jwt"
	Algorithm string         `json:"alg"` // Signing algorithm
	JWK       map[string]any `json:"jwk"` // Public key as JWK
}

// DPoPValidationResult contains the validated DPoP proof information.
type DPoPValidationResult struct {
	JKT    string      // JWK Thumbprint (SHA-256 hash of JWK)
	Claims *DPoPClaims // Validated claims
}

// ValidateDPoPForTokenRequest validates a DPoP proof for the token endpoint.
// It verifies the proof signature, validates claims, and checks for replay attacks.
func ValidateDPoPForTokenRequest(dpopHeader string, httpMethod string, httpURL string, jtiStore *store.JTIStore) (string, error) {
	result, err := ParseAndValidateDPoP(dpopHeader, httpMethod, httpURL, "", 60*time.Second)
	if err != nil {
		return "", err
	}

	// Check for replay attack
	if jtiStore != nil && jtiStore.IsUsed(result.Claims.JTI) {
		return "", ErrDPoPReplayDetected
	}

	// Mark JTI as used (expires after 60 seconds to match timestamp tolerance)
	if jtiStore != nil {
		jtiStore.MarkUsed(result.Claims.JTI, time.Now().Add(60*time.Second))
	}

	return result.JKT, nil
}

// ValidateDPoPForResourceRequest validates a DPoP proof for a resource server request.
// It additionally validates the access token hash (ath claim).
func ValidateDPoPForResourceRequest(dpopHeader string, httpMethod string, httpURL string, accessToken string, jktFromToken string) error {
	// Compute expected access token hash
	expectedATH := ComputeAccessTokenHash(accessToken)

	// Parse and validate DPoP proof
	result, err := ParseAndValidateDPoP(dpopHeader, httpMethod, httpURL, expectedATH, 60*time.Second)
	if err != nil {
		return err
	}

	// Verify JKT matches the one bound to the access token
	if result.JKT != jktFromToken {
		return fmt.Errorf("DPoP proof key mismatch: expected jkt=%s, got jkt=%s", jktFromToken[:16]+"...", result.JKT[:16]+"...")
	}

	return nil
}

// ParseAndValidateDPoP parses and validates a DPoP proof JWT.
// It returns the JWK thumbprint and validated claims.
func ParseAndValidateDPoP(dpopProof string, httpMethod string, httpURL string, expectedATH string, maxAge time.Duration) (*DPoPValidationResult, error) {
	if dpopProof == "" {
		return nil, ErrInvalidDPoPProof
	}

	// Parse JWT header to extract JWK and validate typ
	parts := strings.Split(dpopProof, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidDPoPProof
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: invalid header encoding", ErrInvalidDPoPProof)
	}

	var header DPoPHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("%w: invalid header JSON", ErrInvalidDPoPProof)
	}

	// RFC 9449: typ MUST be "dpop+jwt"
	if header.Type != "dpop+jwt" {
		return nil, ErrDPoPTypMissing
	}

	// RFC 9449: jwk header MUST be present
	if header.JWK == nil || len(header.JWK) == 0 {
		return nil, ErrDPoPJWKMissing
	}

	// Compute JWK thumbprint (jkt) per RFC 7638
	jkt, err := computeJWKThumbprint(header.JWK)
	if err != nil {
		return nil, fmt.Errorf("compute JWK thumbprint: %w", err)
	}

	// Parse JWK and create public key for signature verification
	publicKey, err := parseJWKPublicKey(header.JWK)
	if err != nil {
		return nil, fmt.Errorf("parse JWK public key: %w", err)
	}

	// Parse and verify JWT signature
	token, err := jwt.ParseWithClaims(dpopProof, &DPoPClaims{}, func(token *jwt.Token) (any, error) {
		// Verify algorithm matches header
		if token.Method.Alg() != header.Algorithm {
			return nil, fmt.Errorf("algorithm mismatch")
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDPoPProof, err)
	}

	claims, ok := token.Claims.(*DPoPClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidDPoPProof
	}

	// Validate required claims
	if claims.JTI == "" {
		return nil, fmt.Errorf("%w: jti required", ErrInvalidDPoPProof)
	}

	if claims.HTM == "" {
		return nil, fmt.Errorf("%w: htm required", ErrInvalidDPoPProof)
	}

	if claims.HTU == "" {
		return nil, fmt.Errorf("%w: htu required", ErrInvalidDPoPProof)
	}

	if claims.IAT == 0 {
		return nil, fmt.Errorf("%w: iat required", ErrInvalidDPoPProof)
	}

	// Validate HTM (HTTP method) matches
	if !strings.EqualFold(claims.HTM, httpMethod) {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrDPoPMethodMismatch, httpMethod, claims.HTM)
	}

	// Validate HTU (HTTP URL) matches (without query parameters and fragment)
	normalizedHTU := normalizeURL(claims.HTU)
	normalizedExpectedURL := normalizeURL(httpURL)
	if normalizedHTU != normalizedExpectedURL {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrDPoPURLMismatch, normalizedExpectedURL, normalizedHTU)
	}

	// Validate IAT (issued at) is recent (within maxAge)
	iat := time.Unix(claims.IAT, 0)
	age := time.Since(iat)
	if age < 0 {
		return nil, fmt.Errorf("%w: iat is in the future", ErrDPoPStaleProof)
	}
	if age > maxAge {
		return nil, fmt.Errorf("%w: proof age %v exceeds max %v", ErrDPoPStaleProof, age, maxAge)
	}

	// Validate ATH (access token hash) if expected
	if expectedATH != "" {
		if claims.ATH == "" {
			return nil, fmt.Errorf("%w: ath claim required for resource requests", ErrInvalidDPoPProof)
		}
		if claims.ATH != expectedATH {
			return nil, fmt.Errorf("%w: ath mismatch", ErrInvalidDPoPProof)
		}
	}

	return &DPoPValidationResult{
		JKT:    jkt,
		Claims: claims,
	}, nil
}

// ComputeAccessTokenHash computes the SHA-256 hash of an access token for the ath claim.
func ComputeAccessTokenHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// computeJWKThumbprint computes the JWK thumbprint per RFC 7638.
func computeJWKThumbprint(jwk map[string]any) (string, error) {
	// RFC 7638: Create canonical JSON representation
	// For RSA keys: {"e":"...","kty":"RSA","n":"..."}
	// For EC keys: {"crv":"...","kty":"EC","x":"...","y":"..."}

	kty, ok := jwk["kty"].(string)
	if !ok {
		return "", errors.New("jwk missing kty")
	}

	var canonical map[string]string
	switch kty {
	case "RSA":
		e, eOk := jwk["e"].(string)
		n, nOk := jwk["n"].(string)
		if !eOk || !nOk {
			return "", errors.New("RSA JWK missing e or n")
		}
		canonical = map[string]string{
			"e":   e,
			"kty": "RSA",
			"n":   n,
		}

	case "EC":
		crv, crvOk := jwk["crv"].(string)
		x, xOk := jwk["x"].(string)
		y, yOk := jwk["y"].(string)
		if !crvOk || !xOk || !yOk {
			return "", errors.New("EC JWK missing crv, x, or y")
		}
		canonical = map[string]string{
			"crv": crv,
			"kty": "EC",
			"x":   x,
			"y":   y,
		}

	default:
		return "", fmt.Errorf("unsupported kty: %s", kty)
	}

	// Marshal to canonical JSON (keys sorted alphabetically)
	canonicalJSON, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}

	// Compute SHA-256 hash
	hash := sha256.Sum256(canonicalJSON)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// parseJWKPublicKey parses a JWK and returns the public key for signature verification.
func parseJWKPublicKey(jwkMap map[string]any) (any, error) {
	// Marshal the JWK map to JSON
	jwkJSON, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, fmt.Errorf("marshal JWK: %w", err)
	}

	// Parse using lestrrat-go/jwx library
	key, err := jwk.ParseKey(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("parse JWK: %w", err)
	}

	// Extract the raw public key
	var rawKey any
	if err := key.Raw(&rawKey); err != nil {
		return nil, fmt.Errorf("extract raw key: %w", err)
	}

	return rawKey, nil
}

// normalizeURL removes query parameters and fragment from a URL.
func normalizeURL(rawURL string) string {
	// Remove fragment
	if idx := strings.Index(rawURL, "#"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	// Remove query parameters
	if idx := strings.Index(rawURL, "?"); idx != -1 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}
