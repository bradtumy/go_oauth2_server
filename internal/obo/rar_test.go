package obo

import "testing"

func TestParseRARAcceptsRegisteredDelegatedActionType(t *testing.T) {
	raw := `[{"type":"` + DelegatedActionType + `","locations":["https://merchant.example/mcp"],"actions":["purchase.execute"],"identifier":"merchant:123","constraints":{"max_amount":100}}]`
	details, err := ParseRAR(raw)
	if err != nil {
		t.Fatalf("parse authorization_details: %v", err)
	}
	if len(details) != 1 || details[0].Identifier != "merchant:123" {
		t.Fatalf("unexpected authorization details: %#v", details)
	}
}

func TestParseRARRejectsUnknownTypeAndFields(t *testing.T) {
	tests := []string{
		`[{"type":"unknown-action","locations":["https://merchant.example/mcp"],"actions":["purchase.execute"],"identifier":"merchant:123"}]`,
		`[{"type":"` + DelegatedActionType + `","locations":["https://merchant.example/mcp"],"actions":["purchase.execute"],"identifier":"merchant:123","unknown":true}]`,
	}
	for _, raw := range tests {
		if _, err := ParseRAR(raw); err == nil {
			t.Fatalf("expected invalid authorization details for %s", raw)
		}
	}
}

func TestComputePermsUsesGrantedIdentifier(t *testing.T) {
	service := Service{}
	details := []RAR{{
		Type:       DelegatedActionType,
		Locations:  []string{"https://merchant.example/mcp"},
		Actions:    []string{"purchase.execute", "purchase.refund"},
		Identifier: "merchant:123",
	}}
	perms, granted, _, err := service.ComputePerms("human:123", details, []string{"purchase.execute"})
	if err != nil {
		t.Fatalf("compute permissions: %v", err)
	}
	if len(granted) != 1 || len(granted[0].Actions) != 1 || granted[0].Actions[0] != "purchase.execute" {
		t.Fatalf("unexpected granted details: %#v", granted)
	}
	if len(perms) != 1 || perms[0] != "purchase.execute:merchant:123" {
		t.Fatalf("unexpected compatibility permissions: %#v", perms)
	}
}
