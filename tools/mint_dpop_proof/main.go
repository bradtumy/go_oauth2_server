package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"tokenator/internal/random"
)

func main() {
	var (
		privateKeyPath = flag.String("private-key", "", "path to PEM-encoded private key file (required)")
		httpMethod     = flag.String("method", "POST", "HTTP method (GET, POST, etc.)")
		httpURL        = flag.String("url", "", "HTTP URL (required)")
		accessToken    = flag.String("access-token", "", "access token (for resource server requests)")
		algorithm      = flag.String("algorithm", "RS256", "signing algorithm (RS256, RS384, RS512, ES256, ES384, ES512)")
		generateKey    = flag.Bool("generate-keypair", false, "generate RSA-2048 keypair for testing")
	)
	flag.Parse()

	// Generate keypair mode
	if *generateKey {
		if err := generateKeypair(); err != nil {
			log.Fatalf("generate keypair: %v", err)
		}
		return
	}

	// Validate required parameters
	if *privateKeyPath == "" {
		log.Fatal("private-key is required")
	}
	if *httpURL == "" {
		log.Fatal("url is required")
	}

	// Read private key
	privateKeyBytes, err := os.ReadFile(*privateKeyPath)
	if err != nil {
		log.Fatalf("read private key: %v", err)
	}

	// Parse PEM-encoded private key
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		log.Fatal("failed to parse PEM block containing private key")
	}

	// Parse private key and create public key JWK
	var signingMethod jwt.SigningMethod
	var privateKey any
	var jwk map[string]any

	switch *algorithm {
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
		privateKey, jwk, err = parseRSAKey(block.Bytes)
	case "RS384":
		signingMethod = jwt.SigningMethodRS384
		privateKey, jwk, err = parseRSAKey(block.Bytes)
	case "RS512":
		signingMethod = jwt.SigningMethodRS512
		privateKey, jwk, err = parseRSAKey(block.Bytes)
	case "ES256":
		signingMethod = jwt.SigningMethodES256
		privateKey, jwk, err = parseECDSAKey(block.Bytes)
	case "ES384":
		signingMethod = jwt.SigningMethodES384
		privateKey, jwk, err = parseECDSAKey(block.Bytes)
	case "ES512":
		signingMethod = jwt.SigningMethodES512
		privateKey, jwk, err = parseECDSAKey(block.Bytes)
	default:
		log.Fatalf("unsupported algorithm: %s", *algorithm)
	}

	if err != nil {
		log.Fatalf("parse key: %v", err)
	}

	// Create DPoP proof claims
	now := time.Now().Unix()
	claims := map[string]any{
		"jti": random.NewID(),                  // Unique identifier
		"htm": *httpMethod,                     // HTTP method
		"htu": normalizeURL(*httpURL),          // HTTP URL (without query/fragment)
		"iat": now,                             // Issued at
	}

	// Add access token hash (ath) if provided (for resource server requests)
	if *accessToken != "" {
		ath := computeAccessTokenHash(*accessToken)
		claims["ath"] = ath
	}

	// Create JWT header with typ and jwk
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims(claims))
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk

	// Sign the token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("sign token: %v", err)
	}

	// Output the DPoP proof
	fmt.Print(tokenString)
}

// parseRSAKey parses RSA private key and creates JWK
func parseRSAKey(keyBytes []byte) (*rsa.PrivateKey, map[string]any, error) {
	// Try PKCS#1 format first
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		// Try PKCS#8 format
		parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse RSA private key: %w", err)
		}
		var ok bool
		privateKey, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("not RSA private key")
		}
	}

	// Create JWK from public key
	publicKey := &privateKey.PublicKey
	jwk := map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}

	return privateKey, jwk, nil
}

// parseECDSAKey parses ECDSA private key and creates JWK
func parseECDSAKey(keyBytes []byte) (*ecdsa.PrivateKey, map[string]any, error) {
	// Try EC format first
	privateKey, err := x509.ParseECPrivateKey(keyBytes)
	if err != nil {
		// Try PKCS#8 format
		parsed, err := x509.ParsePKCS8PrivateKey(keyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parse ECDSA private key: %w", err)
		}
		var ok bool
		privateKey, ok = parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil, fmt.Errorf("not ECDSA private key")
		}
	}

	// Get curve name
	var crv string
	switch privateKey.Curve {
	case elliptic.P256():
		crv = "P-256"
	case elliptic.P384():
		crv = "P-384"
	case elliptic.P521():
		crv = "P-521"
	default:
		return nil, nil, fmt.Errorf("unsupported curve")
	}

	// Create JWK from public key
	publicKey := &privateKey.PublicKey
	jwk := map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
		"y":   base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
	}

	return privateKey, jwk, nil
}

// computeAccessTokenHash computes SHA-256 hash of access token for ath claim
func computeAccessTokenHash(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// normalizeURL removes query parameters and fragment from URL
func normalizeURL(rawURL string) string {
	// Remove fragment
	for i, c := range rawURL {
		if c == '#' {
			rawURL = rawURL[:i]
			break
		}
	}
	// Remove query parameters
	for i, c := range rawURL {
		if c == '?' {
			rawURL = rawURL[:i]
			break
		}
	}
	return rawURL
}

// generateKeypair generates an RSA-2048 keypair for testing
func generateKeypair() error {
	// Generate RSA-2048 keypair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	// Encode private key to PKCS#1 PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Encode public key to PKIX PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Write keys to files
	if err := os.WriteFile("dpop-private-key.pem", privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile("dpop-public-key.pem", publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	fmt.Println("✓ Generated RSA-2048 keypair for DPoP:")
	fmt.Println("  Private key: dpop-private-key.pem")
	fmt.Println("  Public key:  dpop-public-key.pem")

	// Also compute and display JWK thumbprint
	jwk := map[string]string{
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
	}
	canonicalJSON, _ := json.Marshal(jwk)
	hash := sha256.Sum256(canonicalJSON)
	jkt := base64.RawURLEncoding.EncodeToString(hash[:])
	fmt.Printf("  JWK Thumbprint: %s\n", jkt)

	return nil
}
