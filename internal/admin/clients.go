package admin

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"tokenator/internal/store"
)

type ClientHandler struct {
	store      store.ClientStore
	adminToken string
}

func NewClientHandler(store store.ClientStore, adminToken string) *ClientHandler {
	return &ClientHandler{store: store, adminToken: adminToken}
}

func (h *ClientHandler) HandleClients(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.listClients(w, r)
	case http.MethodPost:
		h.createClient(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func (h *ClientHandler) HandleClient(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/admin/clients/")
	id = strings.TrimSpace(id)
	if id == "" {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "client_not_found"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.getClient(w, r, id)
	case http.MethodPut:
		h.updateClient(w, r, id)
	case http.MethodDelete:
		h.deleteClient(w, r, id)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func (h *ClientHandler) listClients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.store.ListClients(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "list_failed"})
		return
	}
	writeJSON(w, http.StatusOK, clients)
}

func (h *ClientHandler) createClient(w http.ResponseWriter, r *http.Request) {
	var input store.ClientInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	normalized, err := store.ValidateClientInput(input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	client := clientFromInput(normalized)
	created, err := h.store.CreateClient(r.Context(), client)
	if err != nil {
		if errors.Is(err, store.ErrClientExists) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "client_exists"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "create_failed"})
		return
	}
	h.logChange("create", created)
	writeJSON(w, http.StatusCreated, created)
}

func (h *ClientHandler) getClient(w http.ResponseWriter, r *http.Request, id string) {
	client, ok, err := h.store.GetClient(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "get_failed"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "client_not_found"})
		return
	}
	writeJSON(w, http.StatusOK, client)
}

func (h *ClientHandler) updateClient(w http.ResponseWriter, r *http.Request, id string) {
	var input store.ClientInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_json"})
		return
	}
	if input.ClientID != "" && input.ClientID != id {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "client_id_mismatch"})
		return
	}
	input.ClientID = id
	normalized, err := store.ValidateClientInput(input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	existing, ok, err := h.store.GetClient(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "get_failed"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "client_not_found"})
		return
	}
	client := clientFromInput(normalized)
	client.CreatedAt = existing.CreatedAt
	updated, err := h.store.UpdateClient(r.Context(), client)
	if err != nil {
		if errors.Is(err, store.ErrClientNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "client_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "update_failed"})
		return
	}
	h.logChange("update", updated)
	writeJSON(w, http.StatusOK, updated)
}

func (h *ClientHandler) deleteClient(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.store.DeleteClient(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrClientNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "client_not_found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "delete_failed"})
		return
	}
	h.logChange("delete", store.Client{ID: id})
	w.WriteHeader(http.StatusNoContent)
}

func (h *ClientHandler) authorize(w http.ResponseWriter, r *http.Request) bool {
	if h.adminToken == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "admin_token_unset"})
		return false
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" || !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "missing_token"})
		return false
	}
	token := strings.TrimSpace(auth[len("bearer "):])
	if token != h.adminToken {
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "invalid_token"})
		return false
	}
	return true
}

func (h *ClientHandler) logChange(action string, client store.Client) {
	payload := map[string]any{
		"event":       "admin_client_change",
		"action":      action,
		"client_id":   client.ID,
		"client_type": client.Type,
		"grant_types": client.GrantTypes,
		"scopes":      client.Scopes,
		"audiences":   client.Audiences,
		"timestamp":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("admin change: %s", action)
		return
	}
	log.Printf("%s", data)
}

func clientFromInput(input store.ClientInput) store.Client {
	return store.Client{
		ID:           input.ClientID,
		Type:         input.ClientType,
		Secret:       input.ClientSecret,
		RedirectURIs: input.RedirectURIs,
		GrantTypes:   input.GrantTypes,
		Scopes:       input.Scopes,
		Audiences:    input.Audiences,
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
