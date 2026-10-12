package mcp

import (
	"net/http"
	"sync"
	"time"
)

// RateLimiter is a per-IP token bucket (P1-6 API rate limiting).
// Defaults: 60 requests/sec with burst 60 (generous for MCP clients,
// stops runaway loops and abuse). NOTE: rate is tokens per SECOND.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter creates a limiter with the given rate (tokens/sec) and
// burst capacity.
func NewRateLimiter(rate, burst float64) *RateLimiter {
	return &RateLimiter{
		buckets: make(map[string]*bucket),
		rate:    rate,
		burst:   burst,
		lastGC:  time.Now(),
	}
}

// Allow reports whether a request from the given key (client IP) may pass.
func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	// Opportunistic GC of stale buckets (every 5 min).
	if now.Sub(l.lastGC) > 5*time.Minute {
		for k, b := range l.buckets {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	// Refill.
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// Middleware wraps a handler with per-IP rate limiting. 429 on exceed.
func (l *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r)
		if !l.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited","error_description":"too many requests","timestamp":"` +
				time.Now().UTC().Format("2006-01-02T15:04:05.000Z") + `"}`))
			return
		}
		next.ServeHTTP(w, r)
	})
}
