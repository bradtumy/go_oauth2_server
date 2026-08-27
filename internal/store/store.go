package store

import (
	"errors"
	"sync"
	"time"
)

// AuthorizationCode represents an authorization code grant.
type AuthorizationCode struct {
	Code                string
	ClientID            string
	HumanID             string
	RedirectURI         string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	// Nonce is the OIDC nonce from the authorization request. It is bound into
	// the ID token so a client can tie the token back to its own request.
	Nonce     string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// RefreshToken represents a refresh token record.
type RefreshToken struct {
	Token      string
	ClientID   string
	HumanID    string
	Scope      string
	FamilyID   string
	IssuedAt   time.Time
	ConsumedAt time.Time
	ExpiresAt  time.Time
}

var (
	ErrRefreshTokenNotFound    = errors.New("refresh token not found")
	ErrRefreshTokenConsumed    = errors.New("refresh token already used")
	ErrRefreshTokenFamilyReset = errors.New("refresh token family revoked")
)

type refreshFamily struct {
	Revoked   bool
	RevokedAt time.Time
}

// Store is an in-memory data store for demo purposes.
type Store struct {
	mu              sync.Mutex
	codes           map[string]AuthorizationCode
	refreshTokens   map[string]RefreshToken
	refreshFamilies map[string]refreshFamily
}

// New creates a new Store.
func New() *Store {
	return &Store{
		codes:           make(map[string]AuthorizationCode),
		refreshTokens:   make(map[string]RefreshToken),
		refreshFamilies: make(map[string]refreshFamily),
	}
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
	if token.FamilyID != "" {
		if _, ok := s.refreshFamilies[token.FamilyID]; !ok {
			s.refreshFamilies[token.FamilyID] = refreshFamily{}
		}
	}
}

// GetRefreshToken retrieves a refresh token.
func (s *Store) GetRefreshToken(token string) (RefreshToken, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[token]
	if !ok {
		return RefreshToken{}, false
	}
	if rt.FamilyID != "" {
		if family, ok := s.refreshFamilies[rt.FamilyID]; ok && family.Revoked {
			return RefreshToken{}, false
		}
	}
	return rt, true
}

// DeleteRefreshToken removes a refresh token.
func (s *Store) DeleteRefreshToken(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.refreshTokens, token)
}

func (s *Store) RotateRefreshToken(token string, next RefreshToken) (RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.refreshTokens[token]
	if !ok {
		return RefreshToken{}, ErrRefreshTokenNotFound
	}
	if current.FamilyID != "" {
		if family, ok := s.refreshFamilies[current.FamilyID]; ok && family.Revoked {
			return RefreshToken{}, ErrRefreshTokenFamilyReset
		}
	}
	if !current.ConsumedAt.IsZero() {
		s.revokeFamilyLocked(current.FamilyID)
		return RefreshToken{}, ErrRefreshTokenConsumed
	}
	current.ConsumedAt = time.Now().UTC()
	s.refreshTokens[token] = current
	if next.FamilyID == "" {
		next.FamilyID = current.FamilyID
	}
	s.refreshTokens[next.Token] = next
	if next.FamilyID != "" {
		if _, ok := s.refreshFamilies[next.FamilyID]; !ok {
			s.refreshFamilies[next.FamilyID] = refreshFamily{}
		}
	}
	return current, nil
}

func (s *Store) RevokeRefreshTokenFamily(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rt, ok := s.refreshTokens[token]
	if !ok {
		return
	}
	s.revokeFamilyLocked(rt.FamilyID)
}

func (s *Store) revokeFamilyLocked(familyID string) {
	if familyID == "" {
		return
	}
	s.refreshFamilies[familyID] = refreshFamily{Revoked: true, RevokedAt: time.Now().UTC()}
	for token, rt := range s.refreshTokens {
		if rt.FamilyID == familyID {
			delete(s.refreshTokens, token)
		}
	}
}
