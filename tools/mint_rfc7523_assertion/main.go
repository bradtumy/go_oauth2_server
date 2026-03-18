package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"tokenator/internal/random"
)

func main() {
	var (
		clientID      = flag.String("client-id", "", "client ID (required - becomes iss and sub)")
		privateKeyPEM = flag.String("private-key", "", "path to PEM-encoded private key file (required)")
		audience      = flag.String("audience", "http://localhost:8080/token", "audience (token endpoint URL)")
		algorithm     = flag.String("algorithm", "RS256", "signing algorithm (RS256, RS384, RS512, ES256, ES384, ES512)")
		ttl           = flag.Duration("ttl", 5*time.Minute, "time to live for assertion")
		keyID         = flag.String("kid", "", "key ID (optional)")
		generate      = flag.Bool("generate-keypair", false, "generate RSA-2048 keypair for testing")
	)
	flag.Parse()

	// Generate keypair mode
	if *generate {
		if err := generateKeypair(); err != nil {
			log.Fatalf("generate keypair: %v", err)
		}
		return
	}

	// Validate required parameters
	if *clientID == "" {
		log.Fatal("client-id is required")
	}
	if *privateKeyPEM == "" {
		log.Fatal("private-key is required")
	}

	// Read private key from file
	privateKeyBytes, err := os.ReadFile(*privateKeyPEM)
	if err != nil {
		log.Fatalf("read private key: %v", err)
	}

	// Parse PEM-encoded private key
	block, _ := pem.Decode(privateKeyBytes)
	if block == nil {
		log.Fatal("failed to parse PEM block containing private key")
	}

	// Parse private key based on algorithm
	var signingMethod jwt.SigningMethod
	var privateKey any

	switch *algorithm {
	case "RS256":
		signingMethod = jwt.SigningMethodRS256
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			// Try PKCS8 format
			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatalf("parse RSA private key: %v", err)
			}
		}
	case "RS384":
		signingMethod = jwt.SigningMethodRS384
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatalf("parse RSA private key: %v", err)
			}
		}
	case "RS512":
		signingMethod = jwt.SigningMethodRS512
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatalf("parse RSA private key: %v", err)
			}
		}
	case "ES256":
		signingMethod = jwt.SigningMethodES256
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatalf("parse ECDSA private key: %v", err)
			}
		}
	case "ES384":
		signingMethod = jwt.SigningMethodES384
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatalf("parse ECDSA private key: %v", err)
			}
		}
	case "ES512":
		signingMethod = jwt.SigningMethodES512
		privateKey, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				log.Fatalf("parse ECDSA private key: %v", err)
			}
		}
	default:
		log.Fatalf("unsupported algorithm: %s", *algorithm)
	}

	// Create RFC 7523 compliant claims
	now := time.Now().UTC()
	claims := jwt.RegisteredClaims{
		Issuer:    *clientID, // RFC 7523: iss MUST equal client_id
		Subject:   *clientID, // RFC 7523: sub MUST equal client_id
		Audience:  jwt.ClaimStrings{*audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(*ttl)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        random.NewID(), // jti for replay protection
	}

	// Create token with claims
	token := jwt.NewWithClaims(signingMethod, claims)

	// Add kid header if specified
	if *keyID != "" {
		token.Header["kid"] = *keyID
	}

	// Sign the token
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		log.Fatalf("sign token: %v", err)
	}

	// Output the JWT assertion
	fmt.Print(tokenString)
}

// generateKeypair generates an RSA-2048 keypair for testing.
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
	if err := os.WriteFile("agent-private-key.pem", privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile("agent-public-key.pem", publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}

	fmt.Println("✓ Generated RSA-2048 keypair:")
	fmt.Println("  Private key: agent-private-key.pem")
	fmt.Println("  Public key:  agent-public-key.pem")
	return nil
}
