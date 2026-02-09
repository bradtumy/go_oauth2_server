package session

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	// DefaultIdleTimeout is the default idle timeout for sessions (30 minutes)
	DefaultIdleTimeout = 30 * time.Minute

	// DefaultAbsoluteTimeout is the maximum session lifetime (8 hours)
	DefaultAbsoluteTimeout = 8 * time.Hour

	// ErrSessionNotFound is returned when a session is not found
	ErrSessionNotFound = errors.New("session not found")

	// ErrSessionExpired is returned when a session has expired
	ErrSessionExpired = errors.New("session expired")
)

// Session represents an authenticated user session
type Session struct {
	ID         string
	HumanID    string
	Email      string
	CSRFToken  string
	CreatedAt  time.Time
	LastAccess time.Time
	ExpiresAt  time.Time
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt) || time.Now().After(s.LastAccess.Add(DefaultIdleTimeout))
}

// Store defines the interface for session storage
type Store interface {
	// Create creates a new session
	Create(humanID, email string) (*Session, error)

	// Get retrieves a session by ID
	Get(sessionID string) (*Session, error)

	// Touch updates the last access time of a session
	Touch(sessionID string) error

	// Delete removes a session
	Delete(sessionID string) error

	// Cleanup removes expired sessions
	Cleanup() int
}

// MemoryStore is an in-memory session store
type MemoryStore struct {
	mu          sync.RWMutex
	sessions    map[string]*Session
	idleTimeout time.Duration
}

// NewMemoryStore creates a new in-memory session store
func NewMemoryStore(idleTimeout time.Duration) *MemoryStore {
	if idleTimeout == 0 {
		idleTimeout = DefaultIdleTimeout
	}
	return &MemoryStore{
		sessions:    make(map[string]*Session),
		idleTimeout: idleTimeout,
	}
}

// Create creates a new session
func (s *MemoryStore) Create(humanID, email string) (*Session, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return nil, err
	}

	csrfToken, err := generateCSRFToken()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	sess := &Session{
		ID:         sessionID,
		HumanID:    humanID,
		Email:      email,
		CSRFToken:  csrfToken,
		CreatedAt:  now,
		LastAccess: now,
		ExpiresAt:  now.Add(DefaultAbsoluteTimeout),
	}

	s.mu.Lock()
	s.sessions[sessionID] = sess
	s.mu.Unlock()

	return sess, nil
}

// Get retrieves a session by ID
func (s *MemoryStore) Get(sessionID string) (*Session, error) {
	s.mu.RLock()
	sess, ok := s.sessions[sessionID]
	s.mu.RUnlock()

	if !ok {
		return nil, ErrSessionNotFound
	}

	// Check expiration
	if sess.IsExpired() {
		s.Delete(sessionID)
		return nil, ErrSessionExpired
	}

	return sess, nil
}

// Touch updates the last access time
func (s *MemoryStore) Touch(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[sessionID]
	if !ok {
		return ErrSessionNotFound
	}

	sess.LastAccess = time.Now()
	return nil
}

// Delete removes a session
func (s *MemoryStore) Delete(sessionID string) error {
	s.mu.Lock()
	delete(s.sessions, sessionID)
	s.mu.Unlock()
	return nil
}

// Cleanup removes expired sessions and returns the count
func (s *MemoryStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for id, sess := range s.sessions {
		if sess.IsExpired() {
			delete(s.sessions, id)
			count++
		}
	}

	return count
}

// generateSessionID generates a cryptographically secure session ID
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// generateCSRFToken generates a CSRF token
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
