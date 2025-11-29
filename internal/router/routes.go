package router

import (
	"net/http"

	"go_oauth2_server/internal/httputil"
	"go_oauth2_server/internal/identity"
)

// AuthServer represents the authorization server interface for routing.
type AuthServer interface {
	HandleJWKS(w http.ResponseWriter, r *http.Request)
	HandleAuthorize(w http.ResponseWriter, r *http.Request)
	HandleToken(w http.ResponseWriter, r *http.Request)
	HandleSubjectAssertion(w http.ResponseWriter, r *http.Request)
}

// SetupRoutes configures all the HTTP routes for the authorization server.
func SetupRoutes(authServer AuthServer, identityHandler *identity.Handler) *http.ServeMux {
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/healthz", httputil.MethodHandler(http.MethodGet, func(w http.ResponseWriter, r *http.Request) {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	}))

	// OAuth 2.0 endpoints
	mux.HandleFunc("/.well-known/jwks.json", httputil.MethodHandler(http.MethodGet, authServer.HandleJWKS))
	mux.HandleFunc("/authorize", httputil.MethodHandler(http.MethodGet, authServer.HandleAuthorize))
	mux.HandleFunc("/token", httputil.MethodHandler(http.MethodPost, authServer.HandleToken))
	mux.HandleFunc("/mint-assertion", httputil.MethodHandler(http.MethodPost, authServer.HandleSubjectAssertion))
	mux.HandleFunc("/subject-assertion", httputil.MethodHandler(http.MethodPost, authServer.HandleSubjectAssertion))

	// Identity management endpoints
	mux.HandleFunc("/register/human", httputil.MethodHandler(http.MethodPost, identityHandler.CreateHuman))
	mux.HandleFunc("/register/agent", httputil.MethodHandler(http.MethodPost, identityHandler.CreateAgent))
	mux.HandleFunc("/humans", httputil.MethodHandler(http.MethodGet, identityHandler.ListHumans))
	mux.HandleFunc("/agents", httputil.MethodHandler(http.MethodGet, identityHandler.ListAgents))

	// Dynamic human endpoints
	mux.HandleFunc("/humans/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			identityHandler.GetHuman(w, r)
		case http.MethodDelete:
			identityHandler.DeleteHuman(w, r)
		default:
			httputil.MethodNotAllowed(w, r, http.MethodGet, http.MethodDelete)
		}
	})

	// Dynamic agent endpoints
	mux.HandleFunc("/agents/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			identityHandler.GetAgent(w, r)
		case http.MethodDelete:
			identityHandler.DeleteAgent(w, r)
		default:
			httputil.MethodNotAllowed(w, r, http.MethodGet, http.MethodDelete)
		}
	})

	return mux
}
