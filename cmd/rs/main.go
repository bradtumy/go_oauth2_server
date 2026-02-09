package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"tokenator/internal/config"
	internaljwt "tokenator/internal/jwt"
)

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	var keySet *internaljwt.KeySet
	if cfg.SigningKeyDir != "" {
		keySet, err = internaljwt.LoadKeySetFromDir(cfg.SigningKeyDir, cfg.KeyID)
	} else {
		keySet, err = internaljwt.LoadKeySetFromPEM(cfg.SigningKeyPEM, cfg.KeyID)
	}
	if err != nil {
		log.Fatalf("init signer: %v", err)
	}
	signer, err := internaljwt.NewSignerWithKeySet(cfg.Issuer, cfg.Audience, keySet, cfg.AccessTTL, cfg.RefreshTTL, cfg.AccessTTL)
	if err != nil {
		log.Fatalf("init signer: %v", err)
	}

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
		claims, authResult, err := validateRequest(r, signer, cfg.Audience, account)
		if err != nil {
			// Include authorization result in error response if available
			if authResult != nil {
				writeJSONStatus(w, http.StatusForbidden, map[string]any{
					"error":         err.Error(),
					"authorization": authResult,
				})
			} else {
				writeJSONStatus(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			}
			return
		}
		// For direct user tokens, the subject is the actor
		// For delegated tokens (OBO), act.actor contains the original actor
		actor := nestedString(claims, "act", "actor")
		subject, _ := claims["sub"].(string)
		if actor == "" {
			// No delegation - user is acting as themselves
			actor = subject
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":        "ok",
			"actor":         actor,
			"subject":       subject,
			"resource":      account,
			"authorization": authResult,
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
	Issuer        string
	Audience      string
	SigningKeyPEM []byte
	SigningKeyDir string
	KeyID         string
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
}

func loadConfig() (*resourceConfig, error) {
	issuer := getEnv("ISSUER", "")
	if issuer == "" {
		issuer = getEnv("AS_ISSUER", "http://as:8080")
	}
	audience := getEnv("RS_AUDIENCE", "http://localhost:9090")
	key, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return &resourceConfig{
		Issuer:        issuer,
		Audience:      audience,
		SigningKeyPEM: key.SigningKeyPEM,
		SigningKeyDir: key.SigningKeyDir,
		KeyID:         getEnv("AS_SIGNING_KEY_ID", "dev-rs256"),
		AccessTTL:     15 * time.Minute,
		RefreshTTL:    24 * time.Hour,
	}, nil
}

func validateRequest(r *http.Request, signer *internaljwt.Signer, audience, acctID string) (map[string]any, *AuthorizationResult, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return nil, nil, errors.New("missing authorization header")
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return nil, nil, errors.New("invalid authorization header")
	}
	token := strings.TrimSpace(parts[1])
	claimsRaw, err := signer.Verify(token, audience)
	if err != nil {
		return nil, nil, fmt.Errorf("token verification failed: %w", err)
	}
	sub, ok := claimsRaw["sub"].(string)
	if !ok || sub == "" {
		return nil, nil, errors.New("missing sub claim")
	}
	// For direct user tokens, the subject is the actor
	// For delegated tokens (OBO), act.actor contains the original actor
	actor := nestedString(claimsRaw, "act", "actor")
	if actor == "" {
		// No delegation - user is acting as themselves
		actor = sub
	}
	authResult, err := authorize(acctID, claimsRaw)
	if err != nil {
		return nil, authResult, err
	}
	return claimsRaw, authResult, nil
}

type AuthorizationResult struct {
	Allowed       bool
	MatchedScope  string
	TokenScopes   []string
	RequiredScope string
	Policy        string
	Reason        string
}

func authorize(acctID string, claims map[string]any) (*AuthorizationResult, error) {
	if acctID == "" {
		return nil, errors.New("missing account identifier")
	}

	// Pure OAuth 2.0: Check if the token has required scopes
	scope, ok := claims["scope"].(string)
	if !ok || scope == "" {
		return nil, errors.New("missing scope claim")
	}

	// Parse space-separated scopes
	scopes := strings.Fields(scope)
	scopeSet := make(map[string]bool)
	for _, s := range scopes {
		scopeSet[s] = true
	}

	result := &AuthorizationResult{
		TokenScopes:   scopes,
		RequiredScope: "tickets.read OR orders.read OR orders.write",
		Policy:        "orders_export_policy",
	}

	// Check if token has any of the acceptable scopes for this resource
	// For the /accounts/{id}/orders/export endpoint:
	if scopeSet["tickets.read"] {
		result.Allowed = true
		result.MatchedScope = "tickets.read"
		result.Reason = "Token contains 'tickets.read' scope which grants read access to order export resources"
		return result, nil
	}
	if scopeSet["orders.read"] {
		result.Allowed = true
		result.MatchedScope = "orders.read"
		result.Reason = "Token contains 'orders.read' scope which grants read access to order resources"
		return result, nil
	}
	if scopeSet["orders.write"] {
		result.Allowed = true
		result.MatchedScope = "orders.write"
		result.Reason = "Token contains 'orders.write' scope which grants full access to order resources"
		return result, nil
	}

	result.Allowed = false
	result.Reason = fmt.Sprintf("Token scopes %v do not match required scopes for this resource", scopes)
	return result, errors.New("insufficient scope")
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
