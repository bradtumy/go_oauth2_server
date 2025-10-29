package store

import (
	"errors"
	"sync"
	"time"
)

// Client represents an OAuth client registration.
type Client struct {
	ID           string
	Secret       string
	RedirectURI  string
	Audience     string
	DefaultScope string
}

// AuthorizationCode represents an authorization code grant.
type AuthorizationCode struct {
	Code        string
	ClientID    string
	UserID      string
	RedirectURI string
	Scope       string
	ExpiresAt   time.Time
}

// RefreshToken represents a refresh token record.
type RefreshToken struct {
	Token     string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt time.Time
}

// Store is an in-memory data store for demo purposes.
type Store struct {
	mu            sync.Mutex
	clients       map[string]Client
	codes         map[string]AuthorizationCode
	refreshTokens map[string]RefreshToken
}

// New creates a new Store with default data.
func New(defaultClient Client) *Store {
	return &Store{
		clients:       map[string]Client{defaultClient.ID: defaultClient},
		codes:         make(map[string]AuthorizationCode),
		refreshTokens: make(map[string]RefreshToken),
	}
}

// GetClient returns a client by ID.
func (s *Store) GetClient(id string) (Client, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	client, ok := s.clients[id]
	return client, ok
}

// SaveCode stores an authorization code.
func (s *Store) SaveCode(code AuthorizationCode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[code.Code] = code
}

// ConsumeCode deletes and returns an authorization code.
func (s *Store) ConsumeCode(code string) (AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.codes[code]
	if !ok {
		return AuthorizationCode{}, errors.New("invalid_code")
	}
	delete(s.codes, code)
	return record, nil
}

// SaveRefreshToken stores a refresh token.
func (s *Store) SaveRefreshToken(token RefreshToken) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshTokens[token.Token] = token
}

// GetRefreshToken retrieves a refresh token.
func (s *Store) GetRefreshToken(token string) (RefreshToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[token]
	return rt, ok
}

// DeleteRefreshToken removes a refresh token.
func (s *Store) DeleteRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, token)
}
