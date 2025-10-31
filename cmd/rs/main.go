package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	internaljwt "go_oauth2_server/internal/jwt"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	signer := internaljwt.NewSigner(cfg.Issuer, cfg.Audience, cfg.SigningKey, cfg.KeyID, cfg.AccessTTL, cfg.RefreshTTL, cfg.AccessTTL)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/accounts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		acctID := strings.TrimPrefix(r.URL.Path, "/accounts/")
		if acctID == "" {
			writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "account not specified"})
			return
		}
		// Expect trailing /orders/export
		parts := strings.Split(acctID, "/")
		if len(parts) != 3 || parts[1] != "orders" || parts[2] != "export" {
			writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "unknown route"})
			return
		}
		account := parts[0]
		claims, err := validateRequest(r, signer, cfg.Audience, account)
		if err != nil {
			writeJSONStatus(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
		actor := nestedString(claims, "act", "actor")
		subject, _ := claims["sub"].(string)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "ok",
			"actor":    actor,
			"subject":  subject,
			"resource": account,
		})
	})

	addr := ":9090"
	if v := os.Getenv("RS_LISTEN_ADDR"); v != "" {
		addr = v
	}
	log.Printf("Resource server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

type resourceConfig struct {
	Issuer     string
	Audience   string
	SigningKey []byte
	KeyID      string
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

func loadConfig() (*resourceConfig, error) {
	issuer := getEnv("AS_ISSUER", "http://localhost:8080")
	audience := getEnv("RS_AUDIENCE", "http://localhost:9090")
	keyB64 := getEnv("AS_SIGNING_KEY_BASE64", "ZGV2LXNpZ25pbmcta2V5LTEyMzQ=")
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	return &resourceConfig{
		Issuer:     issuer,
		Audience:   audience,
		SigningKey: key,
		KeyID:      getEnv("AS_SIGNING_KEY_ID", "dev-hs256"),
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 24 * time.Hour,
	}, nil
}

func validateRequest(r *http.Request, signer *internaljwt.Signer, audience, acctID string) (map[string]any, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, errors.New("missing authorization header")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, errors.New("invalid authorization header")
	}
	token := strings.TrimSpace(parts[1])
	claimsRaw, err := signer.Verify(token, audience)
	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}
	sub, ok := claimsRaw["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.New("missing sub claim")
	}
	actor := nestedString(claimsRaw, "act", "actor")
	if actor == "" {
		return nil, errors.New("missing act.actor claim")
	}
	if err := authorize(acctID, claimsRaw); err != nil {
		return nil, err
	}
	return claimsRaw, nil
}

func authorize(acctID string, claims map[string]any) error {
	if acctID == "" {
		return errors.New("missing account identifier")
	}
	expectedPerm := "orders:export:" + acctID
	switch perms := claims["perm"].(type) {
	case []any:
		for _, p := range perms {
			if ps, ok := p.(string); ok && ps == expectedPerm {
				if containsResource(claims, acctID) {
					return nil
				}
			}
		}
	case []string:
		for _, ps := range perms {
			if ps == expectedPerm {
				if containsResource(claims, acctID) {
					return nil
				}
			}
		}
	}
	return errors.New("required permission not present")
}

func containsResource(claims map[string]any, acctID string) bool {
	raw, ok := claims["authorization_details"]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			if detail, ok := item.(map[string]any); ok {
				if matchResource(detail, acctID) {
					return true
				}
			}
		}
	case []map[string]any:
		for _, detail := range v {
			if matchResource(detail, acctID) {
				return true
			}
		}
	}
	return false
}

func matchResource(detail map[string]any, acctID string) bool {
	constraints, ok := detail["constraints"].(map[string]any)
	if !ok {
		return false
	}
	ids, ok := constraints["resource_ids"]
	if !ok {
		return false
	}
	switch val := ids.(type) {
	case []any:
		for _, id := range val {
			if s, ok := id.(string); ok && s == acctID {
				return true
			}
		}
	case []string:
		for _, s := range val {
			if s == acctID {
				return true
			}
		}
	}
	return false
}

func nestedString(claims map[string]any, path ...string) string {
	current := any(claims)
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[key]
		if !ok {
			return ""
		}
	}
	if s, ok := current.(string); ok {
		return s
	}
	return ""
}

func writeJSONStatus(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	writeJSONStatus(w, status, payload)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
