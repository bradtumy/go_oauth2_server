package auth

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"tokenator/internal/store"
)

var (
	ErrInvalidAssertion = errors.New("invalid assertion")
	ErrExpiredAssertion = errors.New("assertion expired")
	ErrInvalidAudience  = errors.New("invalid audience")
	ErrInvalidIssuer    = errors.New("invalid issuer")
	ErrInvalidSubject   = errors.New("invalid subject")
	ErrMissingJTI       = errors.New("jti required")
	ErrReplayDetected   = errors.New("assertion replay detected")
	ErrInvalidPublicKey = errors.New("invalid public key")
	ErrUnsupportedAlg   = errors.New("unsupported algorithm")
)

// AssertionClaims represents the claims in a JWT Bearer Client Assertion (RFC 7523).
type AssertionClaims struct {
	jwt.RegisteredClaims
}

// ValidateJWTAssertion validates a JWT Bearer Client Assertion per RFC 7523.
// It performs signature verification, claims validation, and replay protection.
func ValidateJWTAssertion(
	assertionJWT string,
	client store.Client,
	expectedAudience string,
	jtiStore *store.JTIStore,
) error {
	// 1. Parse public key from client record
	publicKey, err := parsePublicKey(client.PublicKey, client.KeyAlgorithm)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}

	// 2. Parse and verify JWT signature
	token, err := jwt.ParseWithClaims(assertionJWT, &AssertionClaims{}, func(token *jwt.Token) (any, error) {
		// Verify algorithm matches client's registered algorithm
		alg := token.Method.Alg()
		if alg != client.KeyAlgorithm {
			return nil, fmt.Errorf("%w: expected %s, got %s", ErrUnsupportedAlg, client.KeyAlgorithm, alg)
		}
		return publicKey, nil
	})

	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidAssertion, err)
	}

	claims, ok := token.Claims.(*AssertionClaims)
	if !ok || !token.Valid {
		return ErrInvalidAssertion
	}

	// 3. Validate required claims per RFC 7523 Section 3
	// - iss (issuer) must equal client_id
	if claims.Issuer != client.ID {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidIssuer, client.ID, claims.Issuer)
	}

	// - sub (subject) must equal client_id
	if claims.Subject != client.ID {
		return fmt.Errorf("%w: expected %s, got %s", ErrInvalidSubject, client.ID, claims.Subject)
	}

	// - aud (audience) must equal token endpoint
	if len(claims.Audience) == 0 {
		return fmt.Errorf("%w: audience is required", ErrInvalidAudience)
	}
	validAudience := false
	for _, aud := range claims.Audience {
		if aud == expectedAudience {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return fmt.Errorf("%w: expected %s, got %v", ErrInvalidAudience, expectedAudience, claims.Audience)
	}

	// - exp (expiration) is validated automatically by jwt library
	// Additional check: assertion should be short-lived (max 5 minutes from now)
	if claims.ExpiresAt != nil {
		maxExpiration := time.Now().Add(5 * time.Minute)
		if claims.ExpiresAt.After(maxExpiration) {
			return fmt.Errorf("%w: assertion expires too far in future", ErrExpiredAssertion)
		}
	}

	// - jti (JWT ID) is required for replay protection
	if claims.ID == "" {
		return ErrMissingJTI
	}

	// 4. Check for replay attack
	if jtiStore != nil && jtiStore.IsUsed(claims.ID) {
		return ErrReplayDetected
	}

	// 5. Mark JTI as used (expires when assertion expires)
	if jtiStore != nil && claims.ExpiresAt != nil {
		jtiStore.MarkUsed(claims.ID, claims.ExpiresAt.Time)
	}

	return nil
}

// parsePublicKey parses a PEM-encoded public key and returns the appropriate key type.
func parsePublicKey(publicKeyPEM string, algorithm string) (any, error) {
	if publicKeyPEM == "" {
		return nil, errors.New("public key is empty")
	}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block")
	}

	// Try parsing as PKIX public key
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Validate key type matches algorithm
	switch algorithm {
	case "RS256", "RS384", "RS512":
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("algorithm %s requires RSA key, got %T", algorithm, publicKey)
		}
		// Verify RSA key strength (minimum 2048 bits)
		if rsaKey.N.BitLen() < 2048 {
			return nil, fmt.Errorf("RSA key too weak: %d bits (minimum 2048)", rsaKey.N.BitLen())
		}
		return rsaKey, nil

	case "ES256", "ES384", "ES512":
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("algorithm %s requires ECDSA key, got %T", algorithm, publicKey)
		}
		// Verify ECDSA curve strength
		bitSize := ecdsaKey.Params().BitSize
		if bitSize < 256 {
			return nil, fmt.Errorf("ECDSA key too weak: %d bits (minimum 256)", bitSize)
		}
		return ecdsaKey, nil

	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, algorithm)
	}
}

// ValidatePublicKey validates a PEM-encoded public key for use with JWT assertions.
// This should be called during client registration.
func ValidatePublicKey(publicKeyPEM string, algorithm string) error {
	_, err := parsePublicKey(publicKeyPEM, algorithm)
	return err
}
