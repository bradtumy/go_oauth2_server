package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"tokenator/internal/store"
)

// Config represents runtime configuration for the authorization server.
type Config struct {
	Issuer         string
	MetadataIssuer string
	Audience       string
	SigningKeyPEM  []byte
	// SigningKeySource records where the key came from, so a fallback to the
	// committed default is visible rather than silent.
	SigningKeySource           string
	SigningKeyID               string
	SigningKeyDir              string
	SigningKeyRotationInterval time.Duration
	CodeTTL                    time.Duration
	AccessTokenTTL             time.Duration
	RefreshTokenTTL            time.Duration
	OBOTokenTTL                time.Duration
	AdminToken                 string
	AllowLegacy                bool
	DevMode                    bool
	EnableRAR                  bool
	SeedIdentitiesPath         string
	ClientDBPath               string
	ClientStoreDriver          string
	AdminAddr                  string
	AuthorizeRateLimitRPS      int
	AuthorizeRateLimitBurst    int
	TokenRateLimitRPS          int
	TokenRateLimitBurst        int
	IntrospectRateLimitRPS     int
	IntrospectRateLimitBurst   int
	AdminRateLimitRPS          int
	AdminRateLimitBurst        int

	// Upstream OIDC provider used for federated human sign-in. Federation is
	// enabled only when issuer, client ID and client secret are all present.
	UpstreamIssuer       string
	UpstreamClientID     string
	UpstreamClientSecret string
	UpstreamScopes       []string
	UpstreamDisplayName  string
	PublicBaseURL        string

	// Trusted Auth Token (TAT) IdP mode. Tokenator stands in for an external
	// customer IdP, minting tokens for a third-party tenant to consume, so the
	// issuer and audience here are deliberately not tokenator's own.
	// TATTenantHost empty disables the feature.
	//
	// TATIssuer identifies this server to the relying party and must be a URL it
	// can reach, so behind a tunnel it is the public tunnel URL.
	//
	// TATAudience is the relying party's authorization server. It is a separate
	// value from TATTenantHost, which is only the host the signed token is
	// POSTed back to; conflating them causes audience-mismatch rejections.
	TATIssuer                    string
	TATAudience                  string
	TATTenantHost                string
	TATTokenTTL                  time.Duration
	TATScopes                    string
	TATAuthorizationDetailsTypes []string
}

// UpstreamRedirectURL is the callback the upstream provider must be configured
// to redirect to. The path is provider-neutral because the provider itself is
// configurable.
func (c *Config) UpstreamRedirectURL() string {
	base := strings.TrimRight(strings.TrimSpace(c.PublicBaseURL), "/")
	if base == "" {
		base = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	}
	return base + "/auth/sso/callback"
}

const (
	defaultIssuer          = "http://localhost:8080"
	defaultAudience        = "http://localhost:9090"
	defaultSigningKeyID    = "dev-rs256"
	defaultCodeTTLSeconds  = 120
	defaultAccessTTL       = 3600
	defaultRefreshTTL      = 86400
	defaultOBOTTL          = 900
	defaultClientDBPath    = "data/clients.db"
	defaultAdminAddr       = "127.0.0.1:8082"
	defaultAuthorizeRPS    = 5
	defaultAuthorizeBurst  = 10
	defaultTokenRPS        = 10
	defaultTokenBurst      = 20
	defaultIntrospectRPS   = 10
	defaultIntrospectBurst = 20
	defaultAdminRPS        = 5
	defaultAdminBurst      = 10
	defaultTATTokenTTL     = 300
)

const defaultSigningKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCk3F5CWCLo296k
DRBCPt2wuhc9wbAdotnCt6prj+Ue4vQGFXzqybvqEr+M7g8YFOOIGA0jdoWMg7to
ztgLyLqjrq9LWVWI4ZeMalweI8wAQcT49EDrC7d/QITMeie/bQiXDMZOshE6eKkv
N1qjax1tgxiQW2vJNIGuZz3g0ytCjK+2HXxovkkzOm59FEzQ87gYwGQR75AAqnmt
Fa8eFXPGpa7eMSa+yJeQFjX4nQ1e16wnhueibheoJggrSSM+fkO9u5AWg+Synrld
ETb4iMP9ftQW9knkiaABFSGkZ/paMuWhzxaRSym+Z1Cf5amUpqKx0Bi/Ut5lVRJV
RpJA+6qFAgMBAAECggEAP0QKMC+ehfoKgK46tRFnBfEEBkEUEutx4dWV4t0/shCq
UMNiQr/UC0nSlISu6jDp+EoykI9lRL0w6FGoey024qWgw6uutW7NN6eBXleia97R
djBV0V2Xt4/M5qNiKYXwK/dNCtou3l97nZECiYALtQEAJjXPMVGjCoi4KFUhXtH7
yQHfCkoyRyPnIU3aYwzqXdaejyp2uCmLzprpPcg0NoFLh8lASSWUybPws3nEk7Bq
qGfGL9eGSm28gNCMu8O8CDWApOPfAyNi6CWbDBY5xf1uow/q2xX5V5bTPZwC3HsO
HtIiu6+JWcdlYifLUorYwuCeWAt2B7Nn0tsbpH5KKQKBgQDmnjZAms9XsfJ2/t43
L0LQTvx1H9iQUD0sghs1oWDifuAk+KrvfrzX6Cbvqw4dF/CWIl0segSkDHVZwQjP
FVMekQ4fnXTG6OsQeyjrjB2NWhM2oizY7FxzobEu/rhE+DpmlsFLlg80b6ZI+suJ
avAVo82W1rSxedYLd8dEAZIqEwKBgQC3AWlMqLob5ZUZlINyjlZ7VY1+EEUmtXPg
mRD97aLQxO/NG3G8LtMSs/VwXkRy25YZVIN2ZJe5QLsiwSspQ3yJuPfb5bQjWw2E
0CZvW7ZgRJoBFR6jxb3aLAvUoqPqokL6wlVA5VjGP0t4xzCBFVATn3kUWzbWlz2k
aXfpImHsBwKBgQCf0kEy4JaU5cNs6BBEGkKpbjPTT7Cbwp/CeqA0uJQWI2te894y
f5iL4F0rd1Yen3qh8Uq1ChKxRdkFzJs4OEUUR96L1mkZeE1/bHrdUosgbK4oDJgb
9SHVGNdcBDbbxVNjyVJH+cSryDxrEzN/FlcwCAbwY/dxj0fhRq8X2CbddQKBgCXC
+cpiqnxlJB3yIil6K2gpoBeaHdq96Fo422O6LDVt3ZlyB0bwVoducL+uA+u7Wb6C
TNoaKaCFNdgXCePq1ADLFQHf5QrCmAiGtteVkg1NOoXsqLTcca9aFVrb8HzS3IVH
ojXQ3T+TAey7FUwdbLeP2XkU1Tz0WjjZtm95s8DzAoGBAKMKN05H4h2s74TC3EJB
ud70LksnQheSBameXDdKe0t9ocCqYlR3L4ECIE3/qPEeHR+esphI9s4WgivGVZEL
s8Db464pzs9t0Z/+RowMN8nMuwXoybwSJYCdm83GEevJoZ4av5gaJCvIEjGHNCul
odOEQaR0ILGMQJZmpfvekDyK
-----END PRIVATE KEY-----`

// Load loads configuration from environment variables.
func Load() (*Config, error) {
	cfg := &Config{
		Issuer:             firstNonEmpty(getEnv("ISSUER", ""), getEnv("AS_ISSUER", defaultIssuer)),
		MetadataIssuer:     firstNonEmpty(getEnv("AS_METADATA_ISSUER", ""), getEnv("ISSUER", ""), getEnv("AS_ISSUER", defaultIssuer)),
		Audience:           firstNonEmpty(getEnv("RS_AUDIENCE", ""), getEnv("AS_AUDIENCE", defaultAudience)),
		SigningKeyID:       getEnv("AS_SIGNING_KEY_ID", defaultSigningKeyID),
		SigningKeyDir:      getEnv("AS_SIGNING_KEYS_DIR", ""),
		AdminToken:         firstNonEmpty(getEnv("AS_ADMIN_TOKEN", ""), getEnv("ADMIN_TOKEN", "")),
		SeedIdentitiesPath: getEnv("SEED_IDENTITIES_JSON", ""),
		ClientDBPath:       getEnv("AS_CLIENTS_DB", defaultClientDBPath),
		ClientStoreDriver:  firstNonEmpty(getEnv("AS_CLIENT_STORE", ""), store.DefaultClientStoreDriver()),
		AdminAddr:          getEnv("AS_ADMIN_ADDR", defaultAdminAddr),
	}

	if cfg.SigningKeyDir == "" {
		signingKey, source, err := loadSigningKeyPEM()
		if err != nil {
			return nil, err
		}
		cfg.SigningKeyPEM = signingKey
		cfg.SigningKeySource = source
	} else {
		cfg.SigningKeySource = "AS_SIGNING_KEYS_DIR=" + cfg.SigningKeyDir
	}

	rotationSeconds, err := parseDurationSecondsAllowZero("AS_SIGNING_KEY_ROTATION_SECONDS", 0)
	if err != nil {
		return nil, err
	}
	cfg.SigningKeyRotationInterval = rotationSeconds

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

	devMode, err := parseBool("DEV_MODE", false)
	if err != nil {
		return nil, err
	}
	cfg.DevMode = devMode

	// RFC 9396 Rich Authorization Requests. Defaults on; set ENABLE_RAR=false to
	// fall back to scope-only authorization.
	enableRAR, err := parseBool("ENABLE_RAR", true)
	if err != nil {
		return nil, err
	}
	cfg.EnableRAR = enableRAR

	cfg.UpstreamIssuer = strings.TrimSpace(getEnv("UPSTREAM_ISSUER", ""))
	cfg.UpstreamClientID = strings.TrimSpace(getEnv("UPSTREAM_CLIENT_ID", ""))
	cfg.UpstreamClientSecret = strings.TrimSpace(getEnv("UPSTREAM_CLIENT_SECRET", ""))
	cfg.UpstreamDisplayName = firstNonEmpty(getEnv("UPSTREAM_DISPLAY_NAME", ""), "SSO")
	cfg.PublicBaseURL = strings.TrimSpace(getEnv("PUBLIC_BASE_URL", ""))
	cfg.UpstreamScopes = splitAndTrim(getEnv("UPSTREAM_SCOPES", "openid,email,profile"))

	cfg.TATTenantHost = strings.TrimSpace(getEnv("TAT_TENANT_HOST", ""))
	cfg.TATIssuer = firstNonEmpty(getEnv("TAT_ISSUER", ""), cfg.Issuer)
	// Falls back to the tenant host only as a convenience for setups where the
	// authorization server and the callback host really are the same origin.
	cfg.TATAudience = strings.TrimSpace(getEnv("TAT_AUDIENCE", ""))
	if cfg.TATAudience == "" && cfg.TATTenantHost != "" {
		cfg.TATAudience = "https://" + cfg.TATTenantHost
	}
	cfg.TATScopes = strings.TrimSpace(getEnv("TAT_SCOPES", ""))
	cfg.TATAuthorizationDetailsTypes = splitAndTrim(getEnv("TAT_AUTHORIZATION_DETAILS_TYPES", ""))
	tatTokenTTL, err := parseDurationSeconds("TAT_TOKEN_TTL_SECONDS", defaultTATTokenTTL)
	if err != nil {
		return nil, err
	}
	cfg.TATTokenTTL = tatTokenTTL

	authorizeRPS, err := parseIntAllowZero("AS_RATE_LIMIT_AUTHORIZE_RPS", defaultAuthorizeRPS)
	if err != nil {
		return nil, err
	}
	authorizeBurst, err := parseIntAllowZero("AS_RATE_LIMIT_AUTHORIZE_BURST", defaultAuthorizeBurst)
	if err != nil {
		return nil, err
	}
	tokenRPS, err := parseIntAllowZero("AS_RATE_LIMIT_TOKEN_RPS", defaultTokenRPS)
	if err != nil {
		return nil, err
	}
	tokenBurst, err := parseIntAllowZero("AS_RATE_LIMIT_TOKEN_BURST", defaultTokenBurst)
	if err != nil {
		return nil, err
	}
	introspectRPS, err := parseIntAllowZero("AS_RATE_LIMIT_INTROSPECT_RPS", defaultIntrospectRPS)
	if err != nil {
		return nil, err
	}
	introspectBurst, err := parseIntAllowZero("AS_RATE_LIMIT_INTROSPECT_BURST", defaultIntrospectBurst)
	if err != nil {
		return nil, err
	}
	adminRPS, err := parseIntAllowZero("AS_RATE_LIMIT_ADMIN_RPS", defaultAdminRPS)
	if err != nil {
		return nil, err
	}
	adminBurst, err := parseIntAllowZero("AS_RATE_LIMIT_ADMIN_BURST", defaultAdminBurst)
	if err != nil {
		return nil, err
	}
	cfg.AuthorizeRateLimitRPS = authorizeRPS
	cfg.AuthorizeRateLimitBurst = authorizeBurst
	cfg.TokenRateLimitRPS = tokenRPS
	cfg.TokenRateLimitBurst = tokenBurst
	cfg.IntrospectRateLimitRPS = introspectRPS
	cfg.IntrospectRateLimitBurst = introspectBurst
	cfg.AdminRateLimitRPS = adminRPS
	cfg.AdminRateLimitBurst = adminBurst

	return cfg, nil
}

// SigningKeySourceBuiltIn marks a configuration that fell back to the signing
// key committed in this package. That key is public, so anything relying on it
// can have its tokens forged by anyone holding the source.
const SigningKeySourceBuiltIn = "built-in default (PUBLIC, committed in internal/config)"

func loadSigningKeyPEM() ([]byte, string, error) {
	if key := strings.TrimSpace(getEnv("AS_SIGNING_KEY_PEM", "")); key != "" {
		return []byte(key), "AS_SIGNING_KEY_PEM", nil
	}
	if path := strings.TrimSpace(getEnv("AS_SIGNING_KEY_PATH", "")); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, "", fmt.Errorf("read signing key: %w", err)
		}
		return data, "AS_SIGNING_KEY_PATH=" + path, nil
	}
	if strings.TrimSpace(defaultSigningKeyPEM) == "" {
		return nil, "", errors.New("missing signing key")
	}
	return []byte(defaultSigningKeyPEM), SigningKeySourceBuiltIn, nil
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

func parseDurationSecondsAllowZero(env string, fallback int) (time.Duration, error) {
	raw := getEnv(env, "")
	if raw == "" {
		return time.Duration(fallback) * time.Second, nil
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", env, err)
	}
	if val < 0 {
		return 0, fmt.Errorf("%s must be non-negative", env)
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

func parseIntAllowZero(env string, fallback int) (int, error) {
	raw := getEnv(env, "")
	if raw == "" {
		return fallback, nil
	}
	val, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", env, err)
	}
	if val < 0 {
		return 0, fmt.Errorf("%s must be non-negative", env)
	}
	return val, nil
}

// splitAndTrim parses a comma-separated env value into non-empty entries.
func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
