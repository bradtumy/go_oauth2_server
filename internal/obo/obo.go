package obo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	internaljwt "go_oauth2_server/internal/jwt"
)

// RAR represents a Rich Authorization Request entry.
type RAR struct {
	Type        string         `json:"type"`
	Locations   []string       `json:"locations,omitempty"`
	Actions     []string       `json:"actions,omitempty"`
	Datatypes   []string       `json:"datatypes,omitempty"`
	Constraints map[string]any `json:"constraints,omitempty"`
}

// ActClaim captures the OAuth ACT claim payload.
type ActClaim struct {
	Actor      string `json:"actor"`
	ClientID   string `json:"client_id"`
	InstanceID string `json:"instance_id,omitempty"`
}

// Delegation metadata associated with the issued token.
type Delegation struct {
	ConsentID string `json:"consent_id,omitempty"`
	PolicyID  string `json:"policy_id,omitempty"`
	TTL       int    `json:"ttl_sec,omitempty"`
}

// CNF claim for future proof-of-possession integration.
type CNF struct {
	JKT     string `json:"jkt,omitempty"`
	X5TS256 string `json:"x5t#S256,omitempty"`
}

// OBOClaims contains the final claim payload.
type OBOClaims struct {
	Iss string   `json:"iss"`
	Aud string   `json:"aud"`
	Sub string   `json:"sub"`
	Act ActClaim `json:"act"`

	AuthorizationDetails  []RAR      `json:"authorization_details,omitempty"`
	Perm                  []string   `json:"perm,omitempty"`
	HumanEntitlementsHash string     `json:"human_entitlements_hash,omitempty"`
	Delegation            Delegation `json:"delegation,omitempty"`
	CNF                   CNF        `json:"cnf,omitempty"`
	JTI                   string     `json:"jti"`
	IAT                   int64      `json:"iat"`
	EXP                   int64      `json:"exp"`
}

// Service coordinates validation and minting for token exchange.
type Service struct {
	Signer   *internaljwt.Signer
	Issuer   string
	Audience string
	OBOTTL   time.Duration
}

var (
	// ErrUnsupportedTokenType indicates the provided token type is unsupported.
	ErrUnsupportedTokenType = errors.New("unsupported token type")
	// ErrInvalidToken indicates a token failed validation.
	ErrInvalidToken = errors.New("invalid token")
	// ErrNoPermissions indicates the computed permission set is empty.
	ErrNoPermissions = errors.New("no permissions granted after evaluation")
)

// ValidateSubjectToken validates the incoming subject token and returns the human subject identifier.
func (s *Service) ValidateSubjectToken(ctx context.Context, tok, tokType string) (string, internaljwt.MapClaims, error) {
	if tok == "" {
		return "", nil, fmt.Errorf("subject_token is required")
	}
	allowed := map[string]bool{
		"urn:ietf:params:oauth:token-type:access_token": true,
		"urn:ietf:params:oauth:token-type:id_token":     true,
		"": true,
	}
	if !allowed[tokType] {
		return "", nil, ErrUnsupportedTokenType
	}
	claims, err := s.Signer.Verify(tok, s.Audience)
	if err != nil {
		return "", nil, fmt.Errorf("validate subject token: %w", err)
	}
	if iss, ok := claims["iss"].(string); ok && iss != s.Issuer {
		return "", nil, fmt.Errorf("subject token issuer mismatch")
	}
	subject, ok := claims["sub"].(string)
	if !ok || subject == "" {
		return "", nil, fmt.Errorf("subject token missing sub")
	}
	return subject, claims, nil
}

// ResolveAgent resolves the acting agent identity from the actor token or fallback to client context.
func (s *Service) ResolveAgent(ctx context.Context, actorToken, actorType, clientID string) (ActClaim, error) {
	if actorToken == "" {
		if clientID == "" {
			return ActClaim{}, fmt.Errorf("actor_token required when client is anonymous")
		}
		return ActClaim{Actor: fmt.Sprintf("agent:%s", clientID), ClientID: clientID}, nil
	}
	if actorType != "" && actorType != "urn:ietf:params:oauth:token-type:jwt" {
		return ActClaim{}, ErrUnsupportedTokenType
	}
	claims, err := s.verifyActorToken(actorToken)
	if err != nil {
		return ActClaim{}, fmt.Errorf("validate actor token: %w", err)
	}
	act := ActClaim{}
	if actor, ok := claims["actor"].(string); ok {
		act.Actor = actor
	}
	if client, ok := claims["client_id"].(string); ok {
		act.ClientID = client
	}
	if inst, ok := claims["instance_id"].(string); ok {
		act.InstanceID = inst
	}
	if act.Actor == "" {
		if sub, ok := claims["sub"].(string); ok && sub != "" {
			act.Actor = sub
		}
	}
	if act.ClientID == "" {
		act.ClientID = clientID
	}
	if act.Actor == "" {
		return ActClaim{}, fmt.Errorf("actor token missing actor")
	}
	if act.ClientID == "" {
		return ActClaim{}, fmt.Errorf("actor client_id missing")
	}
	return act, nil
}

func (s *Service) verifyActorToken(token string) (internaljwt.MapClaims, error) {
	audiences := []string{s.Issuer}
	if s.Audience != "" && s.Audience != s.Issuer {
		audiences = append(audiences, s.Audience)
	}
	var lastErr error
	for _, aud := range audiences {
		claims, err := s.Signer.Verify(token, aud)
		if err == nil {
			return claims, nil
		}
		lastErr = err
		if !errors.Is(err, internaljwt.ErrAudienceMismatch) {
			return nil, err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, internaljwt.ErrAudienceMismatch
}

// ComputePerms flattens authorization details into permissions and computes a subject hash.
func (s *Service) ComputePerms(humanSub string, act ActClaim, rar []RAR) ([]string, string, error) {
	perms := make([]string, 0)
	for _, entry := range rar {
		if entry.Type == "" {
			continue
		}
		actions := entry.Actions
		if len(actions) == 0 {
			continue
		}
		resourceIDs := extractResourceIDs(entry)
		if len(resourceIDs) == 0 {
			for _, action := range actions {
				perms = append(perms, normalizeAction(action))
			}
			continue
		}
		for _, action := range actions {
			actNorm := normalizeAction(action)
			for _, resource := range resourceIDs {
				perms = append(perms, fmt.Sprintf("%s:%s", actNorm, resource))
			}
		}
	}
	if len(perms) == 0 {
		return nil, "", ErrNoPermissions
	}
	hash := internaljwt.ComputeSubjectHash(humanSub, perms)
	return perms, hash, nil
}

// IssueOBOToken issues an OBO JWT using the signer.
func (s *Service) IssueOBOToken(ctx context.Context, claims OBOClaims) (string, int, error) {
	ttl := s.OBOTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	extra := map[string]any{}
	if claims.HumanEntitlementsHash != "" {
		extra["human_entitlements_hash"] = claims.HumanEntitlementsHash
	}
	if claims.Delegation != (Delegation{}) {
		extra["delegation"] = claims.Delegation
	}
	if claims.CNF != (CNF{}) {
		extra["cnf"] = claims.CNF
	}
	return s.Signer.IssueOBOToken(ctx, claims.Sub, claims.Act.ClientID, claims.Perm, claims.AuthorizationDetails, claims.Act, ttl, extra, claims.Aud)
}

// ParseRAR decodes authorization_details JSON into the RAR structure.
func ParseRAR(raw string) ([]RAR, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var rar []RAR
	if err := json.Unmarshal([]byte(raw), &rar); err != nil {
		return nil, fmt.Errorf("parse authorization_details: %w", err)
	}
	return rar, nil
}

func extractResourceIDs(entry RAR) []string {
	if entry.Constraints == nil {
		return nil
	}
	if val, ok := entry.Constraints["resource_ids"]; ok {
		switch v := val.(type) {
		case []any:
			ids := make([]string, 0, len(v))
			for _, item := range v {
				if s, ok := item.(string); ok {
					ids = append(ids, s)
				}
			}
			return ids
		case []string:
			return v
		}
	}
	return nil
}

func normalizeAction(action string) string {
	a := strings.ToLower(strings.TrimSpace(action))
	return strings.ReplaceAll(a, "::", ":")
}
