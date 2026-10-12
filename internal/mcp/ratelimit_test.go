package mcp

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterAllowsBurst(t *testing.T) {
	l := NewRateLimiter(60, 5)
	for i := 0; i < 5; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("burst capacity must allow %d requests", i+1)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatalf("must exceed burst capacity")
	}
	// Different IP unaffected.
	if !l.Allow("5.6.7.8") {
		t.Fatalf("different IP must have its own bucket")
	}
}

func TestRateLimiterMiddleware429(t *testing.T) {
	l := NewRateLimiter(1, 1) // 1 req/sec, burst 1
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := l.Middleware(next)

	// First request passes.
	req := httptest.NewRequest(http.MethodGet, "/metamcp/a/mcp", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first request must pass, got %d", rr.Code)
	}

	// Second immediate request is limited.
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req)
	if rr2.Code != http.StatusTooManyRequests {
		t.Fatalf("second request must 429, got %d", rr2.Code)
	}
}

// N4 (SaaS 4c): the limiter holds at most rateLimitMaxKeys keys, and Allow stays
// fast when the table is full. Before the fix the map grew without bound and each
// Allow scanned every key under the lock (1.24 ms at 50k keys).
func TestN4RateLimiterIsBoundedAndFast(t *testing.T) {
	l := NewRateLimiter(60, 60)
	const keys = 100000
	var worst time.Duration
	var total time.Duration
	for i := 0; i < keys; i++ {
		key := fmt.Sprintf("10.%d.%d.%d", (i>>16)&255, (i>>8)&255, i&255)
		start := time.Now()
		l.Allow(key)
		el := time.Since(start)
		total += el
		if el > worst {
			worst = el
		}
	}
	if n := len(l.index); n > rateLimitMaxKeys || n != l.order.Len() {
		t.Fatalf("after %d distinct keys the limiter holds %d (list %d), cap %d", keys, n, l.order.Len(), rateLimitMaxKeys)
	}
	if mean := total / keys; mean > 50*time.Microsecond {
		t.Fatalf("mean Allow over the fill = %s, want under 50µs", mean)
	}
	// An evicted client gets a fresh bucket (the LRU is the only state lost).
	if !l.Allow("10.0.0.0") {
		t.Fatalf("an evicted key must start with a full bucket")
	}
}
