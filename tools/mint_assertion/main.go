package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"go_oauth2_server/internal/assertion"
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

	token, err := assertion.MintClientAssertion(assertion.MintOptions{
		Issuer:     *issuer,
		Audience:   *audience,
		ClientID:   *clientID,
		ActorID:    *actorID,
		InstanceID: *instanceID,
		SigningKey: key,
		KeyID:      *keyID,
		TTL:        5 * time.Minute,
	})
	if err != nil {
		log.Fatalf("mint assertion: %v", err)
	}

	fmt.Print(token)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
