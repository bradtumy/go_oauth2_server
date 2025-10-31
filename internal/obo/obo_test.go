package obo

import (
	"context"
	"testing"
	"time"

	internaljwt "go_oauth2_server/internal/jwt"
)

func TestResolveAgentIgnoresSubjectAssertionClientID(t *testing.T) {
	signer := internaljwt.NewSigner("issuer", "aud", []byte("secret"), "", time.Minute, time.Minute, time.Minute)
	service := Service{Signer: signer, Issuer: "issuer", Audience: "aud"}

	token, _, err := signer.IssueSubjectAssertion(context.Background(), "human-subject", time.Minute)
	if err != nil {
		t.Fatalf("issue subject assertion: %v", err)
	}

	claim, err := service.ResolveAgent(context.Background(), token, "urn:ietf:params:oauth:token-type:jwt", "client-app")
	if err != nil {
		t.Fatalf("resolve agent: %v", err)
	}
	if claim.ClientID != "client-app" {
		t.Fatalf("expected client-app client id, got %q", claim.ClientID)
	}
	if claim.Actor != "human-subject" {
		t.Fatalf("expected actor to fallback to subject, got %q", claim.Actor)
	}
}
