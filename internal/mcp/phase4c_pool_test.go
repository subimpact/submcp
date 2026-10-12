package mcp

// SaaS phase 4c regressions for the connection pool (N3, N8). Each test is the
// assertion form of one finding from the phase 4b re-review and must fail on the
// phase 4b code.

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// N3: activePerServer kept a zero entry for every server ever used, and the
// cap check scanned all of them under the lock. After N distinct releases the
// map must be empty and the in-use total must be zero.
func TestN3ActivePerServerDropsZeroEntries(t *testing.T) {
	pool := NewPool(1000, 5, time.Minute)
	bg := context.Background()
	const n = 300
	clients := make([]*UpstreamClient, 0, n)
	for i := 0; i < n; i++ {
		c, err := pool.Acquire(bg, fmt.Sprintf("sess-%d", i), fmt.Sprintf("srv-%d", i), poolFactory)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		clients = append(clients, c)
	}
	if idle, active := pool.Stats(); idle != 0 || active != n {
		t.Fatalf("while held: idle=%d active=%d, want 0 and %d", idle, active, n)
	}
	for i, c := range clients {
		pool.Release(fmt.Sprintf("sess-%d", i), fmt.Sprintf("srv-%d", i), c)
	}
	if got := len(pool.activePerServer); got != 0 {
		t.Fatalf("after %d distinct releases activePerServer holds %d entries, want 0", n, got)
	}
	if idle, active := pool.Stats(); active != 0 {
		t.Fatalf("after the releases active=%d (idle=%d), want 0", active, idle)
	}
}

// N3 (session path): ReleaseSession decrements by the stack length; the entry
// must also go when it reaches zero, and the total must follow.
func TestN3ReleaseSessionDropsZeroEntries(t *testing.T) {
	pool := NewPool(1000, 5, time.Minute)
	bg := context.Background()
	for i := 0; i < 50; i++ {
		sess := fmt.Sprintf("s-%d", i)
		for j := 0; j < 2; j++ {
			if _, err := pool.Acquire(bg, sess, fmt.Sprintf("srv-%d", i), poolFactory); err != nil {
				t.Fatal(err)
			}
		}
		pool.ReleaseSession(sess)
	}
	if got := len(pool.activePerServer); got != 0 {
		t.Fatalf("after ReleaseSession the map holds %d entries, want 0", got)
	}
	if _, active := pool.Stats(); active != 0 {
		t.Fatalf("after ReleaseSession active=%d, want 0", active)
	}
}

// N8: a connect factory that panics must not leak the operator reservation.
func TestN8PanickingFactoryReleasesReservation(t *testing.T) {
	pool := NewPool(10, 1, time.Minute)
	bg := context.Background()
	func() {
		defer func() { _ = recover() }()
		_, _ = pool.Acquire(bg, "s", "srv-a", func() (*UpstreamClient, error) { panic("boom") })
	}()
	if got := len(pool.activePerServer); got != 0 {
		t.Fatalf("a panicking factory left %d reservations", got)
	}
	// The single per-server slot must be usable again.
	if _, err := pool.Acquire(bg, "s", "srv-a", poolFactory); err != nil {
		t.Fatalf("after a panic the server slot is still held: %v", err)
	}
}

// N8: a panicking tenant factory returns its budget unit AND its in-flight slot.
// TenantStats must read 0, and the tenant must still get its full share.
func TestN8PanickingTenantFactoryReturnsBudget(t *testing.T) {
	pool := NewPool(100, 20, time.Minute) // budget 30, per-tenant share 3
	bg := context.Background()
	func() {
		defer func() { _ = recover() }()
		_, _ = pool.AcquireTenant(bg, "s", "srv-x#fp", "tenant-p", func() (*UpstreamClient, error) { panic("boom") })
	}()
	if inUse, _ := pool.TenantStats(); inUse != 0 {
		t.Fatalf("TenantStats after a panicking factory = %d, want 0", inUse)
	}
	for i := 0; i < tenantDefaultPerKey; i++ {
		if _, err := pool.AcquireTenant(bg, "s", fmt.Sprintf("ok-%d#fp", i), "tenant-p", poolFactory); err != nil {
			t.Fatalf("after a panic the tenant's share is short at %d: %v", i, err)
		}
	}
}
