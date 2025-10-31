package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

const (
	maxAttributeEntries  = 50
	maxMetadataEntries   = 50
	maxAttributeKeyLen   = 64
	maxAttributeValueLen = 512
	maxNameLen           = 200
	maxCapabilities      = 200
	maxCapabilityLen     = 128
)

var ErrValidation = errors.New("validation error")

type ValidationDetail struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

type ValidationError struct {
	Details []ValidationDetail `json:"details"`
}

func (v *ValidationError) Error() string {
	if v == nil {
		return ""
	}
	return ErrValidation.Error()
}

func (v *ValidationError) add(field, message string) {
	v.Details = append(v.Details, ValidationDetail{Field: field, Message: message})
}

func (v *ValidationError) hasErrors() bool {
	return v != nil && len(v.Details) > 0
}

type HumanInput struct {
	Email      string            `json:"email"`
	Name       string            `json:"name"`
	TenantID   string            `json:"tenant_id"`
	Attributes map[string]string `json:"attributes"`
}

type AgentInput struct {
	AgentID       string            `json:"agent_id"`
	Name          string            `json:"name"`
	ClientID      string            `json:"client_id"`
	Capabilities  []string          `json:"capabilities"`
	DPoPPublicJWK string            `json:"dpop_public_jwk"`
	PolicyID      string            `json:"policy_id"`
	TenantID      string            `json:"tenant_id"`
	Metadata      map[string]string `json:"metadata"`
}

func ValidateHuman(input HumanInput) (HumanInput, error) {
	var verr *ValidationError

	input.Email = strings.TrimSpace(input.Email)
	input.Name = strings.TrimSpace(input.Name)
	input.TenantID = strings.TrimSpace(input.TenantID)

	if input.Email == "" {
		verr = ensureErr(verr)
		verr.add("email", "email is required")
	} else if !isValidEmail(input.Email) {
		verr = ensureErr(verr)
		verr.add("email", "invalid email format")
	}

	if input.Name == "" {
		verr = ensureErr(verr)
		verr.add("name", "name is required")
	} else if len([]rune(input.Name)) > maxNameLen {
		verr = ensureErr(verr)
		verr.add("name", fmt.Sprintf("name must be <= %d characters", maxNameLen))
	}

	attrs, attrErr := normalizeStringMap("attributes", input.Attributes, maxAttributeEntries)
	if attrErr != nil {
		verr = mergeErr(verr, attrErr)
	}
	input.Attributes = attrs

	if verr.hasErrors() {
		return HumanInput{}, verr
	}

	return input, nil
}

func ValidateAgent(input AgentInput) (AgentInput, error) {
	var verr *ValidationError

	input.AgentID = strings.TrimSpace(input.AgentID)
	input.Name = strings.TrimSpace(input.Name)
	input.ClientID = strings.TrimSpace(input.ClientID)
	input.PolicyID = strings.TrimSpace(input.PolicyID)
	input.TenantID = strings.TrimSpace(input.TenantID)
	input.DPoPPublicJWK = strings.TrimSpace(input.DPoPPublicJWK)

	if input.Name == "" {
		verr = ensureErr(verr)
		verr.add("name", "name is required")
	} else if len([]rune(input.Name)) > maxNameLen {
		verr = ensureErr(verr)
		verr.add("name", fmt.Sprintf("name must be <= %d characters", maxNameLen))
	}

	if input.ClientID == "" {
		verr = ensureErr(verr)
		verr.add("client_id", "client_id is required")
	}

	caps, capErr := normalizeCapabilities(input.Capabilities)
	if capErr != nil {
		verr = mergeErr(verr, capErr)
	}
	input.Capabilities = caps

	meta, metaErr := normalizeStringMap("metadata", input.Metadata, maxMetadataEntries)
	if metaErr != nil {
		verr = mergeErr(verr, metaErr)
	}
	input.Metadata = meta

	if input.DPoPPublicJWK != "" {
		if err := validateJWK(input.DPoPPublicJWK); err != nil {
			verr = ensureErr(verr)
			verr.add("dpop_public_jwk", "invalid JWK: "+err.Error())
		}
	}

	if verr.hasErrors() {
		return AgentInput{}, verr
	}

	return input, nil
}

func isValidEmail(email string) bool {
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	return strings.EqualFold(addr.Address, email)
}

func normalizeStringMap(field string, values map[string]string, maxEntries int) (map[string]string, *ValidationError) {
	if len(values) == 0 {
		return nil, nil
	}
	var verr *ValidationError
	if len(values) > maxEntries {
		verr = ensureErr(verr)
		verr.add(field, fmt.Sprintf("%s must have <= %d entries", field, maxEntries))
	}
	normalized := make(map[string]string, len(values))
	for k, v := range values {
		key := strings.TrimSpace(k)
		val := strings.TrimSpace(v)
		if key == "" {
			verr = ensureErr(verr)
			verr.add(field, "attribute keys must be non-empty")
			continue
		}
		if len([]rune(key)) > maxAttributeKeyLen {
			verr = ensureErr(verr)
			verr.add(field, fmt.Sprintf("attribute key '%s' too long", key))
		}
		if len([]rune(val)) > maxAttributeValueLen {
			verr = ensureErr(verr)
			verr.add(field, fmt.Sprintf("attribute value for '%s' exceeds %d characters", key, maxAttributeValueLen))
		}
		normalized[key] = val
	}
	if verr.hasErrors() {
		return nil, verr
	}
	return normalized, nil
}

func normalizeCapabilities(values []string) ([]string, *ValidationError) {
	if len(values) == 0 {
		return nil, nil
	}
	var verr *ValidationError
	if len(values) > maxCapabilities {
		verr = ensureErr(verr)
		verr.add("capabilities", fmt.Sprintf("capabilities must have <= %d entries", maxCapabilities))
	}
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, raw := range values {
		capability := strings.ToLower(strings.TrimSpace(raw))
		if capability == "" {
			verr = ensureErr(verr)
			verr.add("capabilities", "capability entries must be non-empty")
			continue
		}
		if len([]rune(capability)) > maxCapabilityLen {
			verr = ensureErr(verr)
			verr.add("capabilities", fmt.Sprintf("capability '%s' exceeds %d characters", capability, maxCapabilityLen))
			continue
		}
		if strings.ContainsAny(capability, " \t\n\r") {
			verr = ensureErr(verr)
			verr.add("capabilities", fmt.Sprintf("capability '%s' must not contain whitespace", raw))
			continue
		}
		if _, ok := seen[capability]; ok {
			continue
		}
		seen[capability] = struct{}{}
		normalized = append(normalized, capability)
	}
	if verr.hasErrors() {
		return nil, verr
	}
	return normalized, nil
}

func ensureErr(err *ValidationError) *ValidationError {
	if err == nil {
		return &ValidationError{}
	}
	return err
}

func mergeErr(dst, src *ValidationError) *ValidationError {
	if src == nil || len(src.Details) == 0 {
		return dst
	}
	dst = ensureErr(dst)
	dst.Details = append(dst.Details, src.Details...)
	return dst
}

func validateJWK(raw string) error {
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	kty, ok := payload["kty"].(string)
	if !ok || strings.TrimSpace(kty) == "" {
		return errors.New("missing kty")
	}
	if _, ok := payload["k"].(string); ok {
		return nil
	}
	if _, ok := payload["n"].(string); ok {
		return nil
	}
	if _, ok := payload["x"].(string); ok {
		return nil
	}
	return errors.New("missing key material")
}
