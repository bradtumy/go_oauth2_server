package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"tokenator/internal/identity"
	"tokenator/internal/obo"
	memstore "tokenator/internal/store/mem"
)

func TestTokenExchangeRejectsInvalidAuthorizationDetails(t *testing.T) {
	idStore := memstore.New()
	human, err := idStore.CreateHuman(context.Background(), identity.Human{
		Email: "rar-test@example.com",
		Name:  "RAR Test Human",
	})
	if err != nil {
		t.Fatalf("create human: %v", err)
	}
	_, server := newTestServer(t, idStore)
	defer server.Close()

	assertionForm := url.Values{"email": {human.Email}}
	assertionResp, err := http.PostForm(server.URL+"/subject-assertion", assertionForm)
	if err != nil {
		t.Fatalf("subject assertion request: %v", err)
	}
	defer assertionResp.Body.Close()
	var assertionPayload map[string]any
	if err := json.NewDecoder(assertionResp.Body).Decode(&assertionPayload); err != nil {
		t.Fatalf("decode subject assertion: %v", err)
	}
	subjectToken, _ := assertionPayload["assertion"].(string)
	if subjectToken == "" {
		t.Fatal("missing subject assertion")
	}

	tests := []struct {
		name    string
		details string
	}{
		{name: "unknown type", details: `[{"type":"unknown-action","locations":["http://localhost:9090"],"actions":["orders:export"],"identifier":"acct:123"}]`},
		{name: "unknown field", details: fmt.Sprintf(`[{"type":%q,"locations":["http://localhost:9090"],"actions":["orders:export"],"identifier":"acct:123","surprise":true}]`, obo.DelegatedActionType)},
		{name: "missing identifier", details: fmt.Sprintf(`[{"type":%q,"locations":["http://localhost:9090"],"actions":["orders:export"}]`, obo.DelegatedActionType)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{}
			form.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
			form.Set("client_id", testClientID)
			form.Set("client_secret", testClientSecret)
			form.Set("subject_token", subjectToken)
			form.Set("subject_token_type", "urn:ietf:params:oauth:token-type:access_token")
			form.Set("authorization_details", tc.details)
			resp, err := http.PostForm(server.URL+"/oauth2/token", form)
			if err != nil {
				t.Fatalf("token exchange request: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", resp.StatusCode)
			}
			var payload map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
				t.Fatalf("decode error response: %v", err)
			}
			if payload["error"] != "invalid_authorization_details" {
				t.Fatalf("expected invalid_authorization_details, got %#v", payload)
			}
		})
	}
}
