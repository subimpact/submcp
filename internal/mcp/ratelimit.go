package mcp

import (
	"container/list"
	"net/http"
	"sync"
	"time"
)

// rateLimitMaxKeys bounds the number of keys (client addresses) the limiter
// tracks. Past the cap the least recently used key is evicted (SaaS 4c, N4): the
// old map was never evicted and every Allow was a scan above 10k keys.
const rateLimitMaxKeys = 50000

// RateLimiter is a per-IP token bucket (P1-6 API rate limiting).
// Defaults: 60 requests/sec with burst 60 (generous for MCP clients,
// stops runaway loops and abuse). NOTE: rate is tokens per SECOND.
type RateLimiter struct {
	mu      sync.Mutex
	index   map[string]*list.Element // key -> element whose Value is *limiterEntry
	order   *list.List               // front = most recently used
	maxKeys int
	rate    float64 // tokens per second
	burst   float64
}

type limiterEntry struct {
	key    string
	tokens float64
	last   time.Time
}

// NewRateLimiter creates a limiter with the given rate (tokens/sec) and
// burst capacity.
func NewRateLimiter(rate, burst float64) *RateLimiter {
	return newRateLimiterCapped(rate, burst, rateLimitMaxKeys)
}

func newRateLimiterCapped(rate, burst float64, maxKeys int) *RateLimiter {
	if maxKeys < 1 {
		maxKeys = 1
	}
	return &RateLimiter{
		index:   make(map[string]*list.Element),
		order:   list.New(),
		maxKeys: maxKeys,
		rate:    rate,
		burst:   burst,
	}
}

// Allow reports whether a request from the given key (client IP) may pass.
func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	var e *limiterEntry
	if el, ok := l.index[key]; ok {
		l.order.MoveToFront(el)
		e = el.Value.(*limiterEntry)
	} else {
		e = &limiterEntry{key: key, tokens: l.burst, last: now}
		l.index[key] = l.order.PushFront(e)
		for l.order.Len() > l.maxKeys {
			old := l.order.Back()
			l.order.Remove(old)
			delete(l.index, old.Value.(*limiterEntry).key)
		}
	}
	// Refill.
	elapsed := now.Sub(e.last).Seconds()
	e.tokens += elapsed * l.rate
	if e.tokens > l.burst {
		e.tokens = l.burst
	}
	e.last = now

	if e.tokens >= 1 {
		e.tokens--
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
