package identity

import "testing"

func TestValidateHumanSuccess(t *testing.T) {
	input := HumanInput{
		Email:    "  Alice@example.com  ",
		Name:     " Alice Example ",
		TenantID: " default ",
		Attributes: map[string]string{
			"role": "admin",
		},
	}
	out, err := ValidateHuman(input)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if out.Email != "Alice@example.com" {
		t.Fatalf("expected email trimmed, got %q", out.Email)
	}
	if out.Name != "Alice Example" {
		t.Fatalf("expected trimmed name, got %q", out.Name)
	}
	if out.Attributes["role"] != "admin" {
		t.Fatalf("expected attribute preserved")
	}
}

func TestValidateHumanInvalidEmail(t *testing.T) {
	_, err := ValidateHuman(HumanInput{Email: "not-an-email", Name: "Alice"})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateAgentValidation(t *testing.T) {
	input := AgentInput{
		AgentID:      "ingestor-42",
		Name:         "Data Ingestor",
		ClientID:     "client-xyz",
		Capabilities: []string{" Orders:Export ", "orders:READ"},
		Metadata: map[string]string{
			"env": "dev",
		},
	}
	out, err := ValidateAgent(input)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if len(out.Capabilities) != 2 {
		t.Fatalf("expected capabilities normalized, got %v", out.Capabilities)
	}
	for _, cap := range out.Capabilities {
		if cap != "orders:export" && cap != "orders:read" {
			t.Fatalf("unexpected capability: %s", cap)
		}
	}
}

func TestValidateAgentMissingClient(t *testing.T) {
	_, err := ValidateAgent(AgentInput{Name: "Agent"})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestValidateAgentInvalidJWK(t *testing.T) {
	_, err := ValidateAgent(AgentInput{Name: "Agent", ClientID: "client", DPoPPublicJWK: "{"})
	if err == nil {
		t.Fatal("expected validation error")
	}
}
