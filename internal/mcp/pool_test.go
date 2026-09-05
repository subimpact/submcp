package mcp

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeFactory returns a client whose identity is the counter value.
func fakeFactory(n *int64) func() (*UpstreamClient, error) {
	return func() (*UpstreamClient, error) {
		atomic.AddInt64(n, 1)
		return &UpstreamClient{serverName: "test"}, nil
	}
}

// TestAcquireReleaseReusesIdle: acquire -> release -> acquire must return
// the SAME client instance (idle reuse keyed by serverUUID).
func TestAcquireReleaseReusesIdle(t *testing.T) {
	p := NewPool(10, 5, time.Minute)
	var n int64
	f := fakeFactory(&n)

	c1, err := p.Acquire(context.Background(), "sess1", "srv1", f)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	p.Release("sess1", "srv1", c1)

	c2, err := p.Acquire(context.Background(), "sess2", "srv1", f)
	if err != nil {
		t.Fatalf("second acquire: %v", err)
	}
	if c1 != c2 {
		t.Fatalf("expected idle reuse (same client), got different instances (factory ran %d times)", n)
	}
	if n != 1 {
		t.Fatalf("factory should run exactly once, ran %d", n)
	}
}

// TestReleaseSessionKeysByIdleServerUUID: clients released via
// ReleaseSession must be findable by Acquire (keyed by serverUUID, not
// serverName).
func TestReleaseSessionKeysByIdleServerUUID(t *testing.T) {
	p := NewPool(10, 5, time.Minute)
	var n int64
	f := fakeFactory(&n)

	c1, err := p.Acquire(context.Background(), "sess1", "srv1", f)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	p.ReleaseSession("sess1")

	c2, err := p.Acquire(context.Background(), "sess2", "srv1", f)
	if err != nil {
		t.Fatalf("re-acquire: %v", err)
	}
	if c1 != c2 {
		t.Fatalf("ReleaseSession must return client to the idle pool keyed by serverUUID")
	}
	if n != 1 {
		t.Fatalf("factory should run once, ran %d", n)
	}
}

// TestConcurrentAcquireSameSessionServer: N concurrent acquires for the
// same (session, server) must each get a distinct client, and releasing
// each must not hand an in-use client to another caller. Run with -race.
func TestConcurrentAcquireSameSessionServer(t *testing.T) {
	p := NewPool(100, 20, time.Minute)
	var n int64
	f := fakeFactory(&n)

	const workers = 10
	var wg sync.WaitGroup
	clients := make([]*UpstreamClient, workers)
	errs := make([]error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			clients[i], errs[i] = p.Acquire(context.Background(), "sess", "srv", f)
		}(i)
	}
	wg.Wait()

	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d acquire: %v", i, errs[i])
		}
	}
	// All distinct.
	seen := map[*UpstreamClient]bool{}
	for _, c := range clients {
		if seen[c] {
			t.Fatalf("duplicate client handed out: %p", c)
		}
		seen[c] = true
	}

	// Release all concurrently; then acquire again and verify each
	// released client is reusable and no client is handed out twice.
	var wg2 sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			p.Release("sess", "srv", clients[i])
		}(i)
	}
	wg2.Wait()

	reacquired := make([]*UpstreamClient, workers)
	for i := 0; i < workers; i++ {
		c, err := p.Acquire(context.Background(), "sess2", "srv", f)
		if err != nil {
			t.Fatalf("re-acquire %d: %v", i, err)
		}
		reacquired[i] = c
	}
	seen2 := map[*UpstreamClient]bool{}
	for _, c := range reacquired {
		if seen2[c] {
			t.Fatalf("client %p handed out twice after release", c)
		}
		seen2[c] = true
	}
}

// TestPerServerCapIsGlobal: the per-server cap must limit connections to
// one server across ALL sessions, not per session.
func TestPerServerCapIsGlobal(t *testing.T) {
	p := NewPool(100, 3, time.Minute)
	var n int64
	f := fakeFactory(&n)

	// Fill the cap from three different sessions.
	for i := 0; i < 3; i++ {
		if _, err := p.Acquire(context.Background(), fmt.Sprintf("sess%d", i), "srv", f); err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
	}
	// Fourth acquire from a NEW session must fail (global cap).
	if _, err := p.Acquire(context.Background(), "sess4", "srv", f); err == nil {
		t.Fatalf("expected per-server cap error, got nil")
	}
	if n != 3 {
		t.Fatalf("factory should run 3 times, ran %d", n)
	}
}

// TestCapReservationAtomic: with maxPerServer=1, two concurrent acquires
// must NOT both pass the cap check (check-then-act race regression test).
func TestCapReservationAtomic(t *testing.T) {
	p := NewPool(10, 1, time.Minute)
	var n int64
	f := fakeFactory(&n)

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, results[i] = p.Acquire(context.Background(), "sess", "srv", f)
		}(i)
	}
	wg.Wait()

	okCount := 0
	for _, err := range results {
		if err == nil {
			okCount++
		}
	}
	if okCount != 1 {
		t.Fatalf("expected exactly 1 success with cap=1, got %d (results: %v)", okCount, results)
	}
	if n != 1 {
		t.Fatalf("factory should run once, ran %d", n)
	}
}

// TestFactoryFailureRollsBackReservation: a failed factory must not leave
// a phantom reservation that blocks future acquires.
func TestFactoryFailureRollsBackReservation(t *testing.T) {
	p := NewPool(10, 1, time.Minute)
	fail := func() (*UpstreamClient, error) {
		return nil, fmt.Errorf("boom")
	}
	if _, err := p.Acquire(context.Background(), "sess", "srv", fail); err == nil {
		t.Fatalf("expected factory error")
	}
	// Cap must be free again.
	var n int64
	c, err := p.Acquire(context.Background(), "sess", "srv", fakeFactory(&n))
	if err != nil {
		t.Fatalf("acquire after failed factory: %v", err)
	}
	if c == nil {
		t.Fatalf("nil client")
	}
}

// TestSweepExpiredClosesOnlyExpired: SweepExpired must close idle clients
// older than the TTL and keep fresh ones.
func TestSweepExpiredClosesOnlyExpired(t *testing.T) {
	p := NewPool(10, 5, 50*time.Millisecond)
	var n int64
	f := fakeFactory(&n)

	c1, _ := p.Acquire(context.Background(), "s1", "srv", f)
	p.Release("s1", "srv", c1)
	time.Sleep(80 * time.Millisecond)

	c2, _ := p.Acquire(context.Background(), "s2", "srv", f)
	p.Release("s2", "srv", c2)

	p.SweepExpired()

	// c1's slot should be gone; c2's should remain (fresh).
	idle, _ := p.Stats()
	if idle != 1 {
		t.Fatalf("expected 1 idle after sweep, got %d", idle)
	}
}
