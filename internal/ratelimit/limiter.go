package ratelimit

import (
	"sync"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter is a simple in-memory token bucket rate limiter.
type Limiter struct {
	mu    sync.Mutex
	rate  float64
	burst float64
	store map[string]*bucket
}

// NewLimiter creates a limiter. If rate or burst are non-positive, it returns nil (disabled).
func NewLimiter(rate float64, burst int) *Limiter {
	if rate <= 0 || burst <= 0 {
		return nil
	}
	return &Limiter{
		rate:  rate,
		burst: float64(burst),
		store: make(map[string]*bucket),
	}
}

// Allow reports whether a request should be allowed for the given key.
func (l *Limiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	if key == "" {
		key = "anonymous"
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	b, ok := l.store[key]
	if !ok {
		l.store[key] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(l.burst, b.tokens+elapsed*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
