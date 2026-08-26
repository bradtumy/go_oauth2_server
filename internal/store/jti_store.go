package store

import (
	"sync"
	"time"
)

// JTIStore tracks used JWT IDs to prevent replay attacks for RFC 7523 and RFC 9449.
// It stores JTI values with their expiration times and automatically cleans up expired entries.
type JTIStore struct {
	mu   sync.RWMutex
	used map[string]time.Time // jti -> expiration time
}

// NewJTIStore creates a new JTI store for replay protection.
func NewJTIStore() *JTIStore {
	store := &JTIStore{
		used: make(map[string]time.Time),
	}
	// Start background cleanup goroutine
	go store.cleanupLoop()
	return store
}

// IsUsed checks if a JTI has been used (replay detection).
func (s *JTIStore) IsUsed(jti string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.used[jti]
	return exists
}

// MarkUsed marks a JTI as used with an expiration time.
// The JTI will be automatically cleaned up after expiration.
func (s *JTIStore) MarkUsed(jti string, expiresAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.used[jti] = expiresAt
}

// Cleanup removes expired JTI entries and returns the count of removed entries.
func (s *JTIStore) Cleanup() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	count := 0
	for jti, exp := range s.used {
		if now.After(exp) {
			delete(s.used, jti)
			count++
		}
	}
	return count
}

// Size returns the current number of tracked JTIs.
func (s *JTIStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.used)
}

// cleanupLoop runs periodic cleanup of expired JTIs.
func (s *JTIStore) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		count := s.Cleanup()
		if count > 0 {
			// Could add logging here if logger is available
			_ = count
		}
	}
}
