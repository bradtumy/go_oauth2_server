package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"go_oauth2_server/internal/random"
)

func main() {
	var (
		issuer     = flag.String("issuer", getEnv("AS_ISSUER", "http://localhost:8080"), "issuer for the client assertion")
		audience   = flag.String("audience", getEnv("AS_ISSUER", "http://localhost:8080"), "audience for the client assertion")
		clientID   = flag.String("client", getEnv("AS_DEFAULT_CLIENT_ID", "client-xyz"), "client identifier")
		actorID    = flag.String("actor", "agent:ingestor-42", "actor identifier")
		instanceID = flag.String("instance", "run-"+random.NewID(), "instance identifier")
		keyB64     = flag.String("key", getEnv("AS_SIGNING_KEY_BASE64", "ZGV2LXNpZ25pbmcta2V5LTEyMzQ="), "base64 signing key")
		keyID      = flag.String("kid", getEnv("AS_SIGNING_KEY_ID", "dev-hs256"), "key identifier")
	)
	flag.Parse()

	key, err := base64.StdEncoding.DecodeString(*keyB64)
	if err != nil {
		log.Fatalf("decode key: %v", err)
	}

	now := time.Now().UTC()
	claims := map[string]any{
		"iss":         *issuer,
		"sub":         *actorID,
		"aud":         *audience,
		"iat":         now.Unix(),
		"exp":         now.Add(5 * time.Minute).Unix(),
		"jti":         random.NewID(),
		"actor":       *actorID,
		"client_id":   *clientID,
		"instance_id": *instanceID,
	}
	header := map[string]any{
		"alg": "HS256",
		"typ": "JWT",
	}
	if *keyID != "" {
		header["kid"] = *keyID
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		log.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		log.Fatalf("marshal claims: %v", err)
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	fmt.Print(unsigned + "." + sig)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
