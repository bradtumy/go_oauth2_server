package main

import "testing"

func TestLoadConfigPrefersIssuerEnv(t *testing.T) {
	t.Setenv("ISSUER", "https://issuer.example.com")
	t.Setenv("AS_ISSUER", "https://ignored.example.com")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.Issuer != "https://issuer.example.com" {
		t.Fatalf("expected issuer from ISSUER env, got %q", cfg.Issuer)
	}
}
