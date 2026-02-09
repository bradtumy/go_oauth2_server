package auth

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"tokenator/internal/identity"
	"tokenator/internal/session"
)

// Handler manages authentication requests
type Handler struct {
	Sessions   session.Store
	Identities identity.Store
	DevMode    bool
	templates  *template.Template
}

// NewHandler creates a new authentication handler
func NewHandler(sessions session.Store, identities identity.Store, devMode bool) (*Handler, error) {
	// Load templates from web/templates directory
	tmpl, err := template.ParseGlob(filepath.Join("web", "templates", "*.html"))
	if err != nil {
		return nil, err
	}

	return &Handler{
		Sessions:   sessions,
		Identities: identities,
		DevMode:    devMode,
		templates:  tmpl,
	}, nil
}

// ShowLogin displays the login page
func (h *Handler) ShowLogin(w http.ResponseWriter, r *http.Request) {
	returnTo := r.URL.Query().Get("return_to")

	data := map[string]interface{}{
		"ReturnTo":  returnTo,
		"CSRFToken": "temp-csrf", // TODO: Implement proper CSRF
		"Error":     r.URL.Query().Get("error"),
		"DevMode":   h.DevMode,
	}

	if err := h.templates.ExecuteTemplate(w, "login.html", data); err != nil {
		log.Printf("template error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleLogin processes login form submission
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	returnTo := r.PostFormValue("return_to")

	if email == "" {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Email is required"), http.StatusSeeOther)
		return
	}

	// Get human by email
	human, found := h.Identities.GetHumanByEmail(r.Context(), email)
	if !found {
		http.Redirect(w, r, "/login?error="+url.QueryEscape("Invalid email or password"), http.StatusSeeOther)
		return
	}

	// Verify password (skip in dev mode if no password hash)
	if !h.DevMode || human.PasswordHash != "" {
		if password == "" {
			http.Redirect(w, r, "/login?error="+url.QueryEscape("Password is required"), http.StatusSeeOther)
			return
		}

		if human.PasswordHash == "" {
			http.Redirect(w, r, "/login?error="+url.QueryEscape("No password set for this user"), http.StatusSeeOther)
			return
		}

		if err := VerifyPassword(human.PasswordHash, password); err != nil {
			http.Redirect(w, r, "/login?error="+url.QueryEscape("Invalid email or password"), http.StatusSeeOther)
			return
		}
	}

	// Create session
	sess, err := h.Sessions.Create(human.ID, human.Email)
	if err != nil {
		log.Printf("session creation error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sess.ID,
		Path:     "/",
		MaxAge:   int(session.DefaultAbsoluteTimeout.Seconds()),
		HttpOnly: true,
		Secure:   false, // Set to true in production with HTTPS
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect to return_to or default to root
	if returnTo == "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

// HandleLogout logs out the user
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	// Get session cookie
	cookie, err := r.Cookie("session_id")
	if err == nil {
		// Delete session
		h.Sessions.Delete(cookie.Value)
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// RequireAuth is middleware that requires authentication
func (h *Handler) RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, err := h.GetSession(r)
		if err != nil {
			// Redirect to login with return_to parameter
			returnTo := url.QueryEscape(r.URL.String())
			http.Redirect(w, r, "/login?return_to="+returnTo, http.StatusSeeOther)
			return
		}

		// Touch session to update last access time
		h.Sessions.Touch(sess.ID)

		// Add session to context
		ctx := context.WithValue(r.Context(), sessionContextKey, sess)
		next(w, r.WithContext(ctx))
	}
}

// GetSession retrieves the session from the request
func (h *Handler) GetSession(r *http.Request) (*session.Session, error) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return nil, err
	}

	return h.Sessions.Get(cookie.Value)
}

type contextKey string

const sessionContextKey contextKey = "session"

// SessionFromContext retrieves the session from context
func SessionFromContext(ctx context.Context) (*session.Session, bool) {
	sess, ok := ctx.Value(sessionContextKey).(*session.Session)
	return sess, ok
}

// StartCleanupWorker starts a background worker to cleanup expired sessions
func (h *Handler) StartCleanupWorker(interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			count := h.Sessions.Cleanup()
			if count > 0 {
				log.Printf("Cleaned up %d expired sessions", count)
			}
		}
	}()
}
