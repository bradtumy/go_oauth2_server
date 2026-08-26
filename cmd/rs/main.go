package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"tokenator/internal/auth"
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

	// Initialize resource server with dependencies
	rs := &resourceServer{
		cfg:    cfg,
		signer: signer,
	}

	// Setup routes with middleware composition
	mux := http.NewServeMux()

	// Health check endpoint (no auth required)
	mux.HandleFunc("/healthz", methodHandler(http.MethodGet, rs.handleHealthz))
	mux.HandleFunc("/.well-known/oauth-protected-resource", methodHandler(http.MethodGet, rs.handleProtectedResourceMetadata))

	// Orders context: /orders/{account}/fields (requires orders.read or orders.write scope)
	mux.Handle("/orders/",
		rs.authMiddleware(
			rs.scopeMiddleware([]string{"orders.read", "orders.write"},
				methodHandler(http.MethodGet, rs.handleOrdersContext))))

	// Accounts context: /accounts/{account}/orders/{action} (requires tickets.read or tickets.write scope)
	mux.Handle("/accounts/",
		rs.authMiddleware(
			rs.scopeMiddleware([]string{"orders.read", "orders.write"},
				methodHandler(http.MethodGet, rs.handleAccountsContext))))

	addr := ":9090"
	if v := os.Getenv("RS_LISTEN_ADDR"); v != "" {
		addr = v
	}
	log.Printf("Resource server listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// resourceServer holds dependencies for the resource server
type resourceServer struct {
	cfg    *resourceConfig
	signer *internaljwt.Signer
}

// Context keys for passing data through middleware
type contextKey string

const (
	claimsContextKey     contextKey = "claims"
	authResultContextKey contextKey = "authResult"
)

// getClaimsFromContext retrieves claims from request context
func getClaimsFromContext(ctx context.Context) map[string]any {
	if claims, ok := ctx.Value(claimsContextKey).(map[string]any); ok {
		return claims
	}
	return nil
}

// getAuthResultFromContext retrieves authorization result from request context
func getAuthResultFromContext(ctx context.Context) *AuthorizationResult {
	if result, ok := ctx.Value(authResultContextKey).(*AuthorizationResult); ok {
		return result
	}
	return nil
}

// methodHandler wraps a handler to only allow specified HTTP method
func methodHandler(method string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]any{"error": "method not allowed"})
			return
		}
		handler(w, r)
	}
}

// authMiddleware validates the JWT token and adds claims to context
func (s *resourceServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[AUTH] → Incoming request: method=%s path=%s", r.Method, r.URL.Path)

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("[AUTH] ✗ Authorization header missing")
			writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "missing authorization header"})
			return
		}
		log.Printf("[AUTH] Checking Authorization header")

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 {
			log.Printf("[AUTH] ✗ Invalid authorization header format")
			writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "invalid authorization header"})
			return
		}

		tokenType := strings.ToLower(parts[0])
		token := strings.TrimSpace(parts[1])

		// RFC 9449: Support both Bearer and DPoP tokens
		isDPoP := tokenType == "dpop"
		if !isDPoP && tokenType != "bearer" {
			log.Printf("[AUTH] ✗ Unsupported token type: %s", tokenType)
			writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "unsupported token type"})
			return
		}

		tokenPrefix := token
		if len(token) > 20 {
			tokenPrefix = token[:20] + "..."
		}
		log.Printf("[TOKEN] Verifying %s token: %s", strings.ToUpper(tokenType), tokenPrefix)

		claims, err := s.signer.Verify(token, s.cfg.Audience)
		if err != nil {
			log.Printf("[TOKEN] ✗ Token verification failed: %v", err)
			writeJSONStatus(w, http.StatusForbidden, map[string]any{"error": fmt.Sprintf("token verification failed: %v", err)})
			return
		}

		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			log.Printf("[TOKEN] ✗ Missing or invalid sub claim")
			writeJSONStatus(w, http.StatusForbidden, map[string]any{"error": "missing sub claim"})
			return
		}

		// RFC 9449: Validate DPoP proof if this is a DPoP-bound token
		if isDPoP {
			log.Printf("[DPoP] Validating DPoP-bound token...")

			// Check if token has cnf claim (indicates DPoP binding)
			cnf, hasCnf := claims["cnf"].(map[string]any)
			if !hasCnf {
				log.Printf("[DPoP] ✗ Token is not DPoP-bound (missing cnf claim)")
				writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "token is not DPoP-bound"})
				return
			}

			jkt, ok := cnf["jkt"].(string)
			if !ok || jkt == "" {
				log.Printf("[DPoP] ✗ Invalid cnf claim (missing jkt)")
				writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "invalid cnf claim"})
				return
			}

			// Get DPoP proof from header
			dpopProof := r.Header.Get("DPoP")
			if dpopProof == "" {
				log.Printf("[DPoP] ✗ DPoP header required for DPoP-bound token")
				writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "DPoP header required"})
				return
			}

			// Construct full URL for validation
			fullURL := s.cfg.BaseURL + r.URL.Path
			if r.URL.RawQuery != "" {
				fullURL += "?" + r.URL.RawQuery
			}

			// Validate DPoP proof
			if err := auth.ValidateDPoPForResourceRequest(dpopProof, r.Method, fullURL, token, jkt); err != nil {
				log.Printf("[DPoP] ✗ DPoP proof validation failed: %v", err)
				writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": fmt.Sprintf("invalid DPoP proof: %v", err)})
				return
			}

			log.Printf("[DPoP] ✓ DPoP proof validated successfully")
		} else if cnf, hasCnf := claims["cnf"].(map[string]any); hasCnf {
			// Token is DPoP-bound but client used Bearer token type
			jkt, _ := cnf["jkt"].(string)
			log.Printf("[DPoP] ✗ Token is DPoP-bound (jkt=%s...) but Authorization header uses Bearer", jkt[:16])
			writeJSONStatus(w, http.StatusUnauthorized, map[string]any{"error": "DPoP-bound token requires DPoP authorization type"})
			return
		}

		iss, _ := claims["iss"].(string)
		aud, _ := claims["aud"].(string)

		// Check for standard authorization claims
		var authInfo string
		if scope, ok := claims["scope"].(string); ok && scope != "" {
			// RFC 6749: OAuth 2.0 scope
			authInfo = fmt.Sprintf("scope=%s (RFC 6749)", scope)
		} else if authzDetails, ok := claims["authorization_details"].([]any); ok && len(authzDetails) > 0 {
			// RFC 9396: Rich Authorization Requests
			authInfo = fmt.Sprintf("authorization_details=%d items (RFC 9396)", len(authzDetails))
		} else {
			authInfo = "no standard authorization claims"
		}

		log.Printf("[TOKEN] ✓ Token verified: sub=%s, iss=%s, aud=%s", sub, iss, aud)
		log.Printf("[TOKEN] Authorization: %s", authInfo)

		// Pass claims to next handler via context
		// Convert jwt.MapClaims to map[string]any to avoid type assertion issues
		claimsMap := map[string]any(claims)
		ctx := context.WithValue(r.Context(), claimsContextKey, claimsMap)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// scopeMiddleware checks if the token has required scopes
func (s *resourceServer) scopeMiddleware(requiredScopes []string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[SCOPE] → Checking authorization: required_scopes=%v", requiredScopes)

		claims := getClaimsFromContext(r.Context())
		if claims == nil {
			log.Printf("[SCOPE] ✗ Missing claims in context")
			writeJSONStatus(w, http.StatusForbidden, map[string]any{"error": "missing claims in context"})
			return
		}

		authResult, err := authorize(claims, requiredScopes, s.cfg.EnableRAR)
		if err != nil {
			log.Printf("[AUTHZ] ✗ Authorization DENIED: %s", err.Error())
			if authResult != nil {
				log.Printf("[AUTHZ] Token scopes: %v, Required: %v", authResult.TokenScopes, authResult.RequiredScope)
			}
			writeJSONStatus(w, http.StatusForbidden, map[string]any{
				"error":         err.Error(),
				"authorization": authResult,
			})
			return
		}

		log.Printf("[AUTHZ] ✓ Authorization GRANTED: matched_scope=%s", authResult.MatchedScope)
		log.Printf("[AUTHZ] Reason: %s", authResult.Reason)

		// Pass authorization result to handler via context
		ctx := context.WithValue(r.Context(), authResultContextKey, authResult)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Handler methods

// handleHealthz returns a simple health check response
func (s *resourceServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (s *resourceServer) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	resource := strings.TrimSpace(s.cfg.ProtectedResource)
	if resource == "" {
		resource = strings.TrimSpace(s.cfg.Audience)
	}
	authorizationServers := s.cfg.AuthorizationServers
	if len(authorizationServers) == 0 {
		authorizationServers = []string{s.cfg.Issuer}
	}
	issuer := strings.TrimRight(strings.TrimSpace(s.cfg.Issuer), "/")

	metadata := map[string]any{
		"resource":                 resource,
		"authorization_servers":    authorizationServers,
		"jwks_uri":                 issuer + "/.well-known/jwks.json",
		"bearer_methods_supported": []string{"header"},
	}

	writeJSON(w, http.StatusOK, metadata)
}

// handleOrdersContext handles /orders/{account}/fields endpoint
// This endpoint uses orders.read or orders.write scope (set by middleware)
func (s *resourceServer) handleOrdersContext(w http.ResponseWriter, r *http.Request) {
	// Extract claims and auth result from context (set by middleware)
	claims := getClaimsFromContext(r.Context())
	authResult := getAuthResultFromContext(r.Context())

	// Parse account from path: /orders/{account}/fields
	pathAfterOrders := strings.TrimPrefix(r.URL.Path, "/orders/")
	if pathAfterOrders == "" || pathAfterOrders == r.URL.Path {
		log.Printf("[HANDLER] ✗ Invalid orders path: %s", r.URL.Path)
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "unknown route"})
		return
	}

	// Expect format: {account}/fields
	parts := strings.Split(pathAfterOrders, "/")
	if len(parts) != 2 || parts[1] != "fields" {
		log.Printf("[HANDLER] ✗ Invalid path structure: %s (expected /orders/{account}/fields)", r.URL.Path)
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "unknown route"})
		return
	}
	account := parts[0]

	// Extract actor information
	actor := nestedString(claims, "act", "actor")
	subject, _ := claims["sub"].(string)
	if actor == "" {
		actor = subject
	}

	isDelegated := actor != subject
	log.Printf("[HANDLER] Processing orders fields request: account=%s", account)
	log.Printf("[HANDLER] Actor info: actor=%s, subject=%s, delegated=%v", actor, subject, isDelegated)
	log.Printf("[HANDLER] ✓ Returning fields response for account=%s", account)

	response := map[string]any{
		"status":        "ok",
		"actor":         actor,
		"subject":       subject,
		"resource":      account,
		"action":        "fields",
		"authorization": authResult,
		"fields":        []string{"order_id", "customer_name", "total_amount", "status"},
	}

	writeJSON(w, http.StatusOK, response)
}

// handleAccountsContext handles /accounts/{account}/orders/{action} endpoint
// This endpoint uses tickets.read or tickets.write scope (set by middleware)
func (s *resourceServer) handleAccountsContext(w http.ResponseWriter, r *http.Request) {
	// Extract claims and auth result from context (set by middleware)
	claims := getClaimsFromContext(r.Context())
	authResult := getAuthResultFromContext(r.Context())

	// Parse account ID from path: /accounts/{account}/orders/{action}
	acctID := strings.TrimPrefix(r.URL.Path, "/accounts/")
	if acctID == "" {
		log.Printf("[HANDLER] ✗ Account not specified in path")
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "account not specified"})
		return
	}

	// Validate path structure: expect /orders/{action} suffix (export or fields)
	parts := strings.Split(acctID, "/")
	if len(parts) != 3 || parts[1] != "orders" {
		log.Printf("[HANDLER] ✗ Invalid path structure: %s", r.URL.Path)
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "unknown route"})
		return
	}
	account := parts[0]
	action := parts[2]

	// Validate action is either 'export' or 'fields'
	if action != "export" && action != "fields" {
		log.Printf("[HANDLER] ✗ Unknown action: %s", action)
		writeJSONStatus(w, http.StatusNotFound, map[string]any{"error": "unknown route"})
		return
	}

	// Extract actor information
	// For direct user tokens, the subject is the actor
	// For delegated tokens (OBO), act.actor contains the original actor
	actor := nestedString(claims, "act", "actor")
	subject, _ := claims["sub"].(string)
	if actor == "" {
		// No delegation - user is acting as themselves
		actor = subject
	}

	isDelegated := actor != subject
	log.Printf("[HANDLER] Processing accounts/orders %s request: account=%s", action, account)
	log.Printf("[HANDLER] Actor info: actor=%s, subject=%s, delegated=%v", actor, subject, isDelegated)

	// Return response based on action
	log.Printf("[HANDLER] ✓ Returning authorized response for account=%s, action=%s", account, action)

	response := map[string]any{
		"status":        "ok",
		"actor":         actor,
		"subject":       subject,
		"resource":      account,
		"action":        action,
		"authorization": authResult,
	}

	// Add action-specific data
	if action == "fields" {
		response["fields"] = []string{"order_id", "customer_name", "total_amount", "status"}
	}

	writeJSON(w, http.StatusOK, response)
}

// Deprecated: kept for backward compatibility if needed
func (s *resourceServer) handleOrdersFields(w http.ResponseWriter, r *http.Request) {
	// Auth is handled by middleware - just return the response
	claims := getClaimsFromContext(r.Context())
	subject, _ := claims["sub"].(string)

	log.Printf("[HANDLER] Processing orders fields request: subject=%s", subject)
	log.Printf("[HANDLER] ✓ Returning fields response")

	writeJSON(w, http.StatusOK, map[string]any{
		"message": "orders fields endpoint working",
	})
}

type resourceConfig struct {
	Issuer               string
	Audience             string
	BaseURL              string // RFC 9449: Base URL for DPoP validation
	SigningKeyPEM        []byte
	SigningKeyDir        string
	KeyID                string
	AccessTTL            time.Duration
	RefreshTTL           time.Duration
	EnableRAR            bool
	ProtectedResource    string
	AuthorizationServers []string
}

func loadConfig() (*resourceConfig, error) {
	issuer := getEnv("ISSUER", "")
	if issuer == "" {
		issuer = getEnv("AS_ISSUER", "http://as:8080")
	}
	audience := getEnv("RS_AUDIENCE", "http://localhost:9090")
	protectedResource := getEnv("RS_PROTECTED_RESOURCE", audience)
	authorizationServers := parseCSVEnv("RS_AUTHORIZATION_SERVERS")
	if len(authorizationServers) == 0 {
		authorizationServers = []string{issuer}
	}
	key, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	enableRAR, err := parseBool("ENABLE_RAR", true)
	if err != nil {
		return nil, fmt.Errorf("parse ENABLE_RAR: %w", err)
	}
	baseURL := getEnv("RS_BASE_URL", audience)
	return &resourceConfig{
		Issuer:               issuer,
		Audience:             audience,
		BaseURL:              baseURL,
		SigningKeyPEM:        key.SigningKeyPEM,
		SigningKeyDir:        key.SigningKeyDir,
		KeyID:                getEnv("AS_SIGNING_KEY_ID", "dev-rs256"),
		AccessTTL:            15 * time.Minute,
		RefreshTTL:           24 * time.Hour,
		EnableRAR:            enableRAR,
		ProtectedResource:    protectedResource,
		AuthorizationServers: authorizationServers,
	}, nil
}

func parseCSVEnv(key string) []string {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		out = append(out, value)
	}
	return out
}

// validateRequest is kept for backward compatibility but authorization is now handled by middleware
// This function is no longer used by the refactored handlers
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
	// Note: This old function signature is deprecated - use middleware instead
	// Authorization is now handled separately by scopeMiddleware
	return claimsRaw, nil, nil
}

type AuthorizationResult struct {
	Allowed       bool
	MatchedScope  string
	TokenScopes   []string
	RequiredScope string
	Policy        string
	Reason        string
}

func authorize(claims map[string]any, requiredScopes []string, enableRAR bool) (*AuthorizationResult, error) {
	log.Printf("[AUTHZ] Authorizing request: required_scopes=%v, rar_enabled=%v", requiredScopes, enableRAR)

	// Check for OAuth 2.0 scopes (regular tokens)
	var scopes []string
	var scopeSet = make(map[string]bool)

	scope, hasScope := claims["scope"].(string)
	if hasScope && scope != "" {
		// RFC 6749: OAuth 2.0 scope claim (space-separated string)
		scopes = strings.Fields(scope)
		for _, s := range scopes {
			scopeSet[s] = true
		}
		log.Printf("[AUTHZ] Token has scope claim (OAuth 2.0): %v", scopes)
	} else if enableRAR {
		// Only check authorization_details if RAR is enabled
		if authzDetails, hasAuthzDetails := claims["authorization_details"].([]any); hasAuthzDetails {
			// RFC 9396: Rich Authorization Requests (authorization_details)
			log.Printf("[AUTHZ] Token has authorization_details claim (RFC 9396)")

			// Extract actions from authorization_details
			for _, detail := range authzDetails {
				if detailMap, ok := detail.(map[string]any); ok {
					if actions, ok := detailMap["actions"].([]any); ok {
						for _, action := range actions {
							if actionStr, ok := action.(string); ok {
								scopes = append(scopes, actionStr)
								scopeSet[actionStr] = true
							}
						}
					}
				}
			}
			log.Printf("[AUTHZ] Extracted actions from authorization_details: %v", scopes)
		} else {
			// No standard authorization claims found
			log.Printf("[AUTHZ] ✗ Token has neither 'scope' nor 'authorization_details'")
			return nil, errors.New("missing scope or authorization_details claim")
		}
	} else {
		// RAR disabled but token has authorization_details
		if _, hasAuthzDetails := claims["authorization_details"]; hasAuthzDetails {
			log.Printf("[AUTHZ] ⚠ Token has authorization_details but RAR is disabled (ENABLE_RAR=false)")
		}
		log.Printf("[AUTHZ] ✗ Token missing scope claim (required when RAR disabled)")
		return nil, errors.New("missing scope claim")
	}

	result := &AuthorizationResult{
		TokenScopes:   scopes,
		RequiredScope: strings.Join(requiredScopes, " OR "),
		Policy:        "scope_based_policy",
	}

	// Check if token has any of the required scopes
	for _, requiredScope := range requiredScopes {
		hasScope := scopeSet[requiredScope]
		log.Printf("[AUTHZ] Checking scope '%s'... match=%v", requiredScope, hasScope)
		if hasScope {
			result.Allowed = true
			result.MatchedScope = requiredScope
			result.Reason = fmt.Sprintf("Token contains '%s' scope which grants access to this resource", requiredScope)
			log.Printf("[AUTHZ] ✓ Match found: '%s'", requiredScope)
			return result, nil
		}
	}

	result.Allowed = false
	result.Reason = fmt.Sprintf("Token scopes %v do not match required scopes %v for this resource", scopes, requiredScopes)
	log.Printf("[AUTHZ] ✗ No matching scope found")
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

func parseBool(key string, fallback bool) (bool, error) {
	val := os.Getenv(key)
	if val == "" {
		return fallback, nil
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return false, fmt.Errorf("invalid boolean for %s: %w", key, err)
	}
	return b, nil
}
