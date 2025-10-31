package config

import (
        "encoding/base64"
        "fmt"
        "os"
        "strconv"
        "strings"
        "time"
)

// Config represents runtime configuration for the authorization server.
type Config struct {
        Issuer              string
        Audience            string
        SigningKey          []byte
        SigningKeyID        string
        DefaultClientID     string
        DefaultClientSecret string
        CodeTTL             time.Duration
        AccessTokenTTL      time.Duration
        RefreshTokenTTL     time.Duration
        OBOTokenTTL         time.Duration
        AdminToken          string
        AllowLegacy         bool
        SeedIdentitiesPath  string
}

const (
	defaultIssuer         = "http://localhost:8080"
	defaultAudience       = "http://localhost:9090"
	defaultClientID       = "client-xyz"
	defaultClientSecret   = "secret-xyz"
	defaultSigningKeyB64  = "ZGV2LXNpZ25pbmcta2V5LTEyMzQ=" // base64("dev-signing-key-1234")
	defaultSigningKeyID   = "dev-hs256"
	defaultCodeTTLSeconds = 120
	defaultAccessTTL      = 3600
	defaultRefreshTTL     = 86400
	defaultOBOTTL         = 900
)

// Load loads configuration from environment variables.
func Load() (*Config, error) {
        cfg := &Config{
                Issuer:              firstNonEmpty(getEnv("ISSUER", ""), getEnv("AS_ISSUER", defaultIssuer)),
                Audience:            firstNonEmpty(getEnv("RS_AUDIENCE", ""), getEnv("AS_AUDIENCE", defaultAudience)),
                DefaultClientID:     getEnv("AS_DEFAULT_CLIENT_ID", defaultClientID),
                DefaultClientSecret: getEnv("AS_DEFAULT_CLIENT_SECRET", defaultClientSecret),
                SigningKeyID:        getEnv("AS_SIGNING_KEY_ID", defaultSigningKeyID),
                AdminToken:          getEnv("ADMIN_TOKEN", ""),
                SeedIdentitiesPath:  getEnv("SEED_IDENTITIES_JSON", ""),
        }

	signingKeyRaw := getEnv("AS_SIGNING_KEY_BASE64", defaultSigningKeyB64)
	key, err := base64.StdEncoding.DecodeString(signingKeyRaw)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	cfg.SigningKey = key

	codeTTL, err := parseDurationSeconds("AS_CODE_TTL_SECONDS", defaultCodeTTLSeconds)
	if err != nil {
		return nil, err
	}
	cfg.CodeTTL = codeTTL

	accessTTL, err := parseDurationSeconds("AS_ACCESS_TOKEN_TTL_SECONDS", defaultAccessTTL)
	if err != nil {
		return nil, err
	}
	cfg.AccessTokenTTL = accessTTL

	refreshTTL, err := parseDurationSeconds("AS_REFRESH_TOKEN_TTL_SECONDS", defaultRefreshTTL)
	if err != nil {
		return nil, err
	}
	cfg.RefreshTokenTTL = refreshTTL

	oboTTL, err := parseDurationSeconds("AS_OBO_TOKEN_TTL_SECONDS", defaultOBOTTL)
	if err != nil {
		return nil, err
	}
        cfg.OBOTokenTTL = oboTTL

        allowLegacy, err := parseBool("ALLOW_LEGACY_HARDCODED", false)
        if err != nil {
                return nil, err
        }
        cfg.AllowLegacy = allowLegacy

        return cfg, nil
}

func parseDurationSeconds(env string, fallback int) (time.Duration, error) {
	raw := getEnv(env, "")
	if raw == "" {
		return time.Duration(fallback) * time.Second, nil
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", env, err)
	}
	if val <= 0 {
		return 0, fmt.Errorf("%s must be positive", env)
	}
	return time.Duration(val) * time.Second, nil
}

func getEnv(key, fallback string) string {
        if v := os.Getenv(key); v != "" {
                return v
        }
        return fallback
}

func parseBool(env string, fallback bool) (bool, error) {
        raw := getEnv(env, "")
        if raw == "" {
                return fallback, nil
        }
        switch strings.ToLower(strings.TrimSpace(raw)) {
        case "1", "true", "yes", "y":
                return true, nil
        case "0", "false", "no", "n":
                return false, nil
        default:
                return false, fmt.Errorf("invalid %s: %s", env, raw)
        }
}

func firstNonEmpty(values ...string) string {
        for _, v := range values {
                if strings.TrimSpace(v) != "" {
                        return v
                }
        }
        return ""
}
