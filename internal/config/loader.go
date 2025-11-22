package config

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"go_oauth2_server/internal/identity"
)

// LoadDotEnv loads environment variables from a .env file if it exists.
// It will not overwrite existing environment variables.
func LoadDotEnv() {
	file := ".env"
	f, err := os.Open(file)
	if err != nil {
		return
	}
	defer f.Close()
	
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, value)
		}
	}
}

// LogConfiguration logs the current configuration in a structured way.
// Sensitive values like secrets are masked.
func LogConfiguration(cfg *Config) {
	log.Printf("config: issuer=%s audience=%s allow_legacy=%t admin_token_set=%t seed=%s default_client_id=%s default_client_secret=%s code_ttl=%s access_ttl=%s refresh_ttl=%s obo_ttl=%s",
		cfg.Issuer,
		cfg.Audience,
		cfg.AllowLegacy,
		cfg.AdminToken != "",
		cfg.SeedIdentitiesPath,
		cfg.DefaultClientID,
		MaskSecret(cfg.DefaultClientSecret),
		cfg.CodeTTL,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
		cfg.OBOTokenTTL,
	)
}

// MaskSecret masks a secret string, showing only the first and last 2 characters.
func MaskSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	if len(secret) <= 4 {
		return "****"
	}
	return secret[:2] + strings.Repeat("*", len(secret)-4) + secret[len(secret)-2:]
}

// SeedIdentities loads and creates identities from a JSON seed file.
func SeedIdentities(ctx context.Context, store identity.Store, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read seed file: %w", err)
	}
	
	var doc struct {
		Humans []struct {
			ID         string            `json:"id"`
			Email      string            `json:"email"`
			Name       string            `json:"name"`
			TenantID   string            `json:"tenant_id"`
			Attributes map[string]string `json:"attributes"`
		} `json:"humans"`
		Agents []struct {
			ID            string            `json:"id"`
			AgentID       string            `json:"agent_id"`
			Name          string            `json:"name"`
			ClientID      string            `json:"client_id"`
			Capabilities  []string          `json:"capabilities"`
			DPoPPublicJWK string            `json:"dpop_public_jwk"`
			PolicyID      string            `json:"policy_id"`
			TenantID      string            `json:"tenant_id"`
			Metadata      map[string]string `json:"metadata"`
		} `json:"agents"`
	}
	
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse seed file: %w", err)
	}
	
	// Seed humans
	for _, raw := range doc.Humans {
		input, err := identity.ValidateHuman(identity.HumanInput{
			Email:      raw.Email,
			Name:       raw.Name,
			TenantID:   raw.TenantID,
			Attributes: raw.Attributes,
		})
		if err != nil {
			log.Printf("seed human skipped: %v", err)
			continue
		}
		
		human := identity.Human{
			ID:         strings.TrimSpace(raw.ID),
			Email:      input.Email,
			Name:       input.Name,
			TenantID:   input.TenantID,
			Attributes: input.Attributes,
		}
		
		if _, err := store.CreateHuman(ctx, human); err != nil {
			if errors.Is(err, identity.ErrHumanEmailExists) {
				log.Printf("seed human skipped (exists): %s", human.Email)
				continue
			}
			return fmt.Errorf("seed human %s: %w", human.Email, err)
		}
		log.Printf("seeded human: %s (%s)", human.ID, human.Email)
	}
	
	// Seed agents
	for _, raw := range doc.Agents {
		input, err := identity.ValidateAgent(identity.AgentInput{
			AgentID:       raw.AgentID,
			Name:          raw.Name,
			ClientID:      raw.ClientID,
			Capabilities:  raw.Capabilities,
			DPoPPublicJWK: raw.DPoPPublicJWK,
			PolicyID:      raw.PolicyID,
			TenantID:      raw.TenantID,
			Metadata:      raw.Metadata,
		})
		if err != nil {
			log.Printf("seed agent skipped: %v", err)
			continue
		}
		
		agent := identity.Agent{
			ID:            strings.TrimSpace(raw.ID),
			AgentID:       input.AgentID,
			Name:          input.Name,
			ClientID:      input.ClientID,
			Capabilities:  input.Capabilities,
			DPoPPublicJWK: input.DPoPPublicJWK,
			PolicyID:      input.PolicyID,
			TenantID:      input.TenantID,
			Metadata:      input.Metadata,
		}
		
		if _, err := store.CreateAgent(ctx, agent); err != nil {
			if errors.Is(err, identity.ErrAgentLabelExists) {
				log.Printf("seed agent skipped (label exists): %s", agent.AgentID)
				continue
			}
			return fmt.Errorf("seed agent %s: %w", agent.Name, err)
		}
		log.Printf("seeded agent: %s (%s)", agent.ID, agent.Name)
	}
	
	return nil
}
