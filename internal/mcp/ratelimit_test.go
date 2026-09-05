package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
