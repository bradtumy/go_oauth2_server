package identity_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go_oauth2_server/internal/identity"
	memstore "go_oauth2_server/internal/store/mem"
)

func TestCreateHumanHandler(t *testing.T) {
	store := memstore.New()
	handler := identity.NewHandler(store, "secret")

	payload := identity.HumanInput{Email: "bob@example.com", Name: "Bob"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/register/human", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", "secret")
	rec := httptest.NewRecorder()
	handler.CreateHuman(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/register/human", bytes.NewReader(body))
	req2.Header.Set("X-Admin-Token", "secret")
	rec2 := httptest.NewRecorder()
	handler.CreateHuman(rec2, req2)
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 duplicate, got %d", rec2.Code)
	}
}

func TestCreateAgentValidation(t *testing.T) {
	store := memstore.New()
	handler := identity.NewHandler(store, "")

	payload := identity.AgentInput{Name: "Agent", ClientID: ""}
	body, _ := json.Marshal(payload)
	rec := httptest.NewRecorder()
	handler.CreateAgent(rec, httptest.NewRequest(http.MethodPost, "/register/agent", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing client id, got %d", rec.Code)
	}

	payload = identity.AgentInput{Name: "Agent", ClientID: "client", DPoPPublicJWK: "bad"}
	body, _ = json.Marshal(payload)
	rec = httptest.NewRecorder()
	handler.CreateAgent(rec, httptest.NewRequest(http.MethodPost, "/register/agent", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid jwk")
	}
}

func TestListHandlers(t *testing.T) {
	store := memstore.New()
	handler := identity.NewHandler(store, "")
	ctx := context.Background()

	if _, err := store.CreateHuman(ctx, identity.Human{Email: "eve@example.com", Name: "Eve"}); err != nil {
		t.Fatalf("seed human: %v", err)
	}
	if _, err := store.CreateAgent(ctx, identity.Agent{Name: "Agent", ClientID: "client", Capabilities: []string{"orders:read"}}); err != nil {
		t.Fatalf("seed agent: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ListHumans(rec, httptest.NewRequest(http.MethodGet, "/humans", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	handler.ListAgents(rec, httptest.NewRequest(http.MethodGet, "/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
