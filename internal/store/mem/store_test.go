package mem

import (
	"context"
	"testing"

	"go_oauth2_server/internal/identity"
)

func TestHumanCRUD(t *testing.T) {
	ctx := context.Background()
	store := New()

	h1, err := store.CreateHuman(ctx, identity.Human{Email: "alice@example.com", Name: "Alice"})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}
	if h1.ID == "" {
		t.Fatal("expected generated ID")
	}
	if _, err := store.CreateHuman(ctx, identity.Human{Email: "ALICE@example.com", Name: "Alice"}); err == nil {
		t.Fatal("expected duplicate email error")
	}

	h2, ok := store.GetHuman(ctx, h1.ID)
	if !ok || h2.Email != "alice@example.com" {
		t.Fatalf("expected to retrieve human, got %+v", h2)
	}

	list, err := store.ListHumans(ctx, 10, 0)
	if err != nil || len(list) != 1 {
		t.Fatalf("expected list with 1 human, got %v %v", len(list), err)
	}

	if err := store.DeleteHuman(ctx, h1.ID); err != nil {
		t.Fatalf("delete human: %v", err)
	}
	if _, ok := store.GetHuman(ctx, h1.ID); ok {
		t.Fatal("expected human removed")
	}
}

func TestAgentIndexes(t *testing.T) {
	ctx := context.Background()
	store := New()

	a1, err := store.CreateAgent(ctx, identity.Agent{Name: "Agent One", ClientID: "client-xyz", AgentID: "primary", Capabilities: []string{"orders:read"}})
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}

	if _, err := store.CreateAgent(ctx, identity.Agent{Name: "Agent Two", ClientID: "client-xyz", AgentID: "primary"}); err == nil {
		t.Fatal("expected duplicate agent label error")
	}

	agent, ok := store.GetAgent(ctx, a1.ID)
	if !ok || agent.Name != "Agent One" {
		t.Fatalf("expected to get agent")
	}

	agents, err := store.ListAgentsByClient(ctx, "client-xyz")
	if err != nil || len(agents) != 1 {
		t.Fatalf("expected one agent for client, got %v %v", len(agents), err)
	}

	if err := store.DeleteAgent(ctx, a1.ID); err != nil {
		t.Fatalf("delete agent: %v", err)
	}
	if _, ok := store.GetAgent(ctx, a1.ID); ok {
		t.Fatal("expected agent removed")
	}
}
