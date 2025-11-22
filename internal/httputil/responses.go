package httputil

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// WriteJSON writes a JSON response with the given status code and payload.
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write json: %v", err)
	}
}

// WriteOAuthError writes an OAuth 2.0 error response.
func WriteOAuthError(w http.ResponseWriter, status int, code, description string) {
	WriteJSON(w, status, map[string]any{
		"error":             code,
		"error_description": description,
	})
}

// WriteCacheableJSON writes a JSON response with appropriate caching headers.
func WriteCacheableJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Pragma", "no-cache")
	WriteJSON(w, status, payload)
}

// MethodHandler creates a handler that only accepts the specified HTTP method.
func MethodHandler(method string, fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			WriteOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
			return
		}
		fn(w, r)
	}
}

// MethodNotAllowed writes a method not allowed error with the allowed methods.
func MethodNotAllowed(w http.ResponseWriter, r *http.Request, allowed ...string) {
	if len(allowed) > 0 {
		w.Header().Set("Allow", strings.Join(allowed, ", "))
	}
	WriteOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
}