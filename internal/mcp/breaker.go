package mcp

import (
	"sync"
	"time"
)

// Breaker is a per-server circuit breaker (P1-6).
//
// States:
//   - closed:   normal operation; failures counted
//   - open:     fail fast (skip upstream) for the cooldown window
//   - half-open: after cooldown, one probe request is allowed; success
//     closes the circuit, failure reopens it
//
// When the breaker opens, the server's error_status is set to ERROR in
// the DB (quarantine — GetActiveServersForNamespace already filters
// error_status = 'NONE'); on recovery it is reset to NONE.
type Breaker struct {
	mu       sync.Mutex
	failures int
	state    string // "closed" | "open" | "half-open"
	openedAt time.Time
	probes   int
}

const (
	breakerMaxFailures = 5
	breakerCooldown    = 30 * time.Second
	breakerMaxProbes   = 1
)

func NewBreaker() *Breaker {
	return &Breaker{state: "closed"}
}

// Allow reports whether a request may proceed to the upstream.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case "open":
		if time.Since(b.openedAt) > breakerCooldown {
			b.state = "half-open"
			b.probes = 0
			return true
		}
		return false
	case "half-open":
		if b.probes < breakerMaxProbes {
			b.probes++
			return true
		}
		return false
	default:
		return true
	}
}

// Success records a successful call: resets failures, closes the circuit.
func (b *Breaker) Success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	if b.state != "closed" {
		b.state = "closed"
	}
}

// Failure records a failed call; opens the circuit after max failures.
// Returns true if the circuit just transitioned to open (caller should
// write error_status = ERROR).
func (b *Breaker) Failure() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.state == "half-open" {
		// Probe failed: reopen immediately.
		b.state = "open"
		b.openedAt = time.Now()
		return true
	}
	if b.failures >= breakerMaxFailures && b.state == "closed" {
		b.state = "open"
		b.openedAt = time.Now()
		return true
	}
	return false
}

// State returns the current state (for metrics).
func (b *Breaker) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}
