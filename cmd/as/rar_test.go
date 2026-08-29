package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"tokenator/internal/obo"
	memstore "tokenator/internal/store/mem"
)

func TestTokenExchangeRejectsInvalidAuthorizationDetails(t *testing.T) {
	_, server := newTestServer(t, memstore.New())
	defer server.Close()

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
