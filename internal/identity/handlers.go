package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"crypto/subtle"
)

type Handler struct {
	Store      Store
	AdminToken string
}

const defaultLimit = 50

func NewHandler(store Store, adminToken string) *Handler {
	return &Handler{Store: store, AdminToken: strings.TrimSpace(adminToken)}
}

func (h *Handler) CreateHuman(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	var input HumanInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body", nil)
		return
	}
	sanitized, err := ValidateHuman(input)
	if err != nil {
		writeValidationError(w, err)
		return
	}
	human, err := h.Store.CreateHuman(r.Context(), Human{
		Email:      sanitized.Email,
		Name:       sanitized.Name,
		TenantID:   sanitized.TenantID,
		Attributes: sanitized.Attributes,
	})
	if err != nil {
		if errors.Is(err, ErrHumanEmailExists) {
			detail := []ValidationDetail{{Field: "email", Message: "email already registered"}}
			writeError(w, http.StatusBadRequest, "validation_error", "validation failed", detail)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusCreated, human)
}

func (h *Handler) GetHuman(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/humans/")
	human, ok := h.Store.GetHuman(r.Context(), id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "human not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, human)
}

func (h *Handler) ListHumans(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	limit, offset, err := parsePagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	humans, err := h.Store.ListHumans(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": humans,
		"count": len(humans),
	})
}

func (h *Handler) DeleteHuman(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/humans/")
	if err := h.Store.DeleteHuman(r.Context(), id); err != nil {
		if errors.Is(err, ErrHumanNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "human not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) CreateAgent(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	var input AgentInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid JSON body", nil)
		return
	}
	sanitized, err := ValidateAgent(input)
	if err != nil {
		writeValidationError(w, err)
		return
	}
	agent, err := h.Store.CreateAgent(r.Context(), Agent{
		AgentID:       sanitized.AgentID,
		Name:          sanitized.Name,
		ClientID:      sanitized.ClientID,
		Capabilities:  sanitized.Capabilities,
		DPoPPublicJWK: sanitized.DPoPPublicJWK,
		PolicyID:      sanitized.PolicyID,
		TenantID:      sanitized.TenantID,
		Metadata:      sanitized.Metadata,
	})
	if err != nil {
		if errors.Is(err, ErrAgentLabelExists) {
			detail := []ValidationDetail{{Field: "agent_id", Message: "agent_id already registered for client"}}
			writeError(w, http.StatusBadRequest, "validation_error", "validation failed", detail)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusCreated, agent)
}

func (h *Handler) GetAgent(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/agents/")
	agent, ok := h.Store.GetAgent(r.Context(), id)
	if !ok {
		writeError(w, http.StatusNotFound, "not_found", "agent not found", nil)
		return
	}
	writeJSON(w, http.StatusOK, agent)
}

func (h *Handler) ListAgents(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	limit, offset, err := parsePagination(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error(), nil)
		return
	}
	agents, err := h.Store.ListAgents(r.Context(), limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": agents,
		"count": len(agents),
	})
}

func (h *Handler) DeleteAgent(w http.ResponseWriter, r *http.Request) {
	if !h.authorize(w, r) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/agents/")
	if err := h.Store.DeleteAgent(r.Context(), id); err != nil {
		if errors.Is(err, ErrAgentNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "agent not found", nil)
			return
		}
		writeError(w, http.StatusInternalServerError, "server_error", err.Error(), nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) bool {
	if h.AdminToken == "" {
		return true
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(r.Header.Get("X-Admin-Token"))), []byte(h.AdminToken)) == 1 {
		return true
	}
	writeError(w, http.StatusUnauthorized, "access_denied", "admin token required", nil)
	return false
}

func parsePagination(r *http.Request) (int, int, error) {
	limit := defaultLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		val, err := strconv.Atoi(raw)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid limit")
		}
		limit = val
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		val, err := strconv.Atoi(raw)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid offset")
		}
		offset = val
	}
	if offset < 0 {
		return 0, 0, fmt.Errorf("offset must be >= 0")
	}
	return limit, offset, nil
}

func writeValidationError(w http.ResponseWriter, err error) {
	var verr *ValidationError
	if errors.As(err, &verr) {
		writeError(w, http.StatusBadRequest, "validation_error", "validation failed", verr.Details)
		return
	}
	writeError(w, http.StatusBadRequest, "validation_error", "validation failed", nil)
}

func writeError(w http.ResponseWriter, status int, code, description string, details []ValidationDetail) {
	payload := map[string]any{
		"error":             code,
		"error_description": description,
	}
	if len(details) > 0 {
		payload["details"] = details
	}
	writeJSON(w, status, payload)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
