package mcp

import (
	"testing"
	"time"
)

func TestBreakerOpensAfterFailures(t *testing.T) {
	b := NewBreaker()
	for i := 0; i < breakerMaxFailures; i++ {
		if !b.Allow() {
			t.Fatalf("breaker must allow while closed (failure %d)", i+1)
		}
		b.Failure()
	}
	if b.State() != "open" {
		t.Fatalf("breaker must open after %d failures, state=%s", breakerMaxFailures, b.State())
	}
	if b.Allow() {
		t.Fatalf("open breaker must fail fast")
	}
}

func TestBreakerHalfOpenProbe(t *testing.T) {
	b := NewBreaker()
	for i := 0; i < breakerMaxFailures; i++ {
		b.Failure()
	}
	// Force cooldown expiry.
	b.mu.Lock()
	b.openedAt = time.Now().Add(-2 * breakerCooldown)
	b.mu.Unlock()

	if !b.Allow() {
		t.Fatalf("after cooldown the breaker must allow a probe")
	}
	if b.State() != "half-open" {
		t.Fatalf("probe must transition to half-open, state=%s", b.State())
	}
	// Probe success closes the circuit.
	b.Success()
	if b.State() != "closed" {
		t.Fatalf("probe success must close the circuit, state=%s", b.State())
	}
}

func TestBreakerProbeFailureReopens(t *testing.T) {
	b := NewBreaker()
	for i := 0; i < breakerMaxFailures; i++ {
		b.Failure()
	}
	b.mu.Lock()
	b.openedAt = time.Now().Add(-2 * breakerCooldown)
	b.mu.Unlock()

	if !b.Allow() {
		t.Fatalf("probe must be allowed")
	}
	if !b.Failure() {
		t.Fatalf("probe failure must report the open transition")
	}
	if b.State() != "open" {
		t.Fatalf("probe failure must reopen the circuit, state=%s", b.State())
	}
}
