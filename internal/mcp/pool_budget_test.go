package mcp

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func poolFactory() (*UpstreamClient, error) { return &UpstreamClient{}, nil }

// PoC6: tenant tarpits must not take the whole pool. Eight tenants each try four
// slow connections (the per-tenant cap). Only the tenant budget (30 of 100) may
// be used, so an operator acquire still succeeds.
func TestPoC6_TenantBudgetLeavesOperatorHeadroom(t *testing.T) {
	pool := NewPool(100, 20, time.Minute)
	ctx := context.Background()
	acquired, refused := 0, 0
	for tenant := 0; tenant < 8; tenant++ {
		key := fmt.Sprintf("tenant-%d", tenant)
		for i := 0; i < 4; i++ {
			_, err := pool.AcquireTenant(ctx, fmt.Sprintf("sess-%d-%d", tenant, i),
				fmt.Sprintf("srv-%d-%d#fp", tenant, i), key, poolFactory)
			switch {
			case err == nil:
				acquired++
			case errors.Is(err, errTenantBudgetFull):
				refused++
			default:
				t.Fatalf("unexpected error: %v", err)
			}
		}
	}
	if acquired != 30 || refused != 2 {
		t.Fatalf("tenant acquires: got %d granted and %d refused, want 30 and 2", acquired, refused)
	}
	if inUse, budget := pool.TenantStats(); inUse != 30 || budget != 30 {
		t.Fatalf("tenant budget %d of %d, want 30 of 30", inUse, budget)
	}
	if _, err := pool.Acquire(ctx, "operator-session", "operator-legacy-server-uuid", poolFactory); err != nil {
		t.Fatalf("operator acquire must succeed while the tenant budget is spent: %v", err)
	}
}

// Per-tenant in-flight cap: the fifth concurrent acquire waits for a slot and
// gives up when its context ends. Releasing a slot lets the next one through.
func TestTenantInFlightCapWaitsWithinContext(t *testing.T) {
	pool := NewPool(100, 20, time.Minute)
	bg := context.Background()
	var held []*UpstreamClient
	for i := 0; i < 4; i++ {
		c, err := pool.AcquireTenant(bg, "s", fmt.Sprintf("srv-%d#fp", i), "tenant-a", poolFactory)
		if err != nil {
			t.Fatalf("acquire %d: %v", i, err)
		}
		held = append(held, c)
	}
	short, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	defer cancel()
	_, err := pool.AcquireTenant(short, "s", "srv-4#fp", "tenant-a", poolFactory)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a fifth in-flight acquire must wait and then time out, got %v", err)
	}
	// Another tenant is not affected by tenant-a's cap.
	if _, err := pool.AcquireTenant(bg, "s", "srv-other#fp", "tenant-b", poolFactory); err != nil {
		t.Fatalf("a different tenant must not be capped by tenant-a: %v", err)
	}
	pool.Release("s", "srv-0#fp", held[0])
	if _, err := pool.AcquireTenant(bg, "s2", "srv-4#fp", "tenant-a", poolFactory); err != nil {
		t.Fatalf("after a release the next acquire must succeed: %v", err)
	}
}

// Releasing tenant clients (one at a time, or the whole session) returns budget.
func TestTenantBudgetIsReturnedOnRelease(t *testing.T) {
	pool := NewPool(10, 20, time.Minute) // budget 3
	bg := context.Background()
	c1, _ := pool.AcquireTenant(bg, "s1", "a#fp", "t1", poolFactory)
	c2, _ := pool.AcquireTenant(bg, "s1", "b#fp", "t2", poolFactory)
	c3, _ := pool.AcquireTenant(bg, "s2", "c#fp", "t3", poolFactory)
	if _, err := pool.AcquireTenant(bg, "s3", "d#fp", "t4", poolFactory); !errors.Is(err, errTenantBudgetFull) {
		t.Fatalf("budget of 3 must refuse a fourth tenant connection: %v", err)
	}
	pool.Release("s1", "a#fp", c1)
	if _, err := pool.AcquireTenant(bg, "s3", "d#fp", "t4", poolFactory); err != nil {
		t.Fatalf("a released connection must return its budget: %v", err)
	}
	pool.ReleaseSession("s1") // releases c2
	_ = c3
	if inUse, _ := pool.TenantStats(); inUse != 2 {
		t.Fatalf("after releasing session s1 the budget in use is %d, want 2", inUse)
	}
	_ = c2
}

// A failed connect returns the budget unit and the tenant slot.
func TestTenantFailedConnectRollsBack(t *testing.T) {
	pool := NewPool(10, 20, time.Minute) // budget 3
	bg := context.Background()
	failing := func() (*UpstreamClient, error) { return nil, errors.New("connect refused") }
	for i := 0; i < 6; i++ {
		if _, err := pool.AcquireTenant(bg, "s", fmt.Sprintf("x%d#fp", i), "t1", failing); err == nil {
			t.Fatal("a failing factory must return an error")
		}
	}
	if inUse, _ := pool.TenantStats(); inUse != 0 {
		t.Fatalf("failed connects leaked %d budget units", inUse)
	}
	if _, err := pool.AcquireTenant(bg, "s", "ok#fp", "t1", poolFactory); err != nil {
		t.Fatalf("the tenant must still be able to connect after failures: %v", err)
	}
}

// SetTenantLimits applies the configured budget and per-tenant cap.
func TestSetTenantLimits(t *testing.T) {
	pool := NewPool(100, 20, time.Minute)
	pool.SetTenantLimits(5, 1)
	bg := context.Background()
	if _, err := pool.AcquireTenant(bg, "s", "a#fp", "t", poolFactory); err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(bg, 20*time.Millisecond)
	defer cancel()
	if _, err := pool.AcquireTenant(short, "s", "b#fp", "t", poolFactory); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("per-tenant cap of 1 must hold: %v", err)
	}
	if _, budget := pool.TenantStats(); budget != 5 {
		t.Fatalf("budget = %d, want 5", budget)
	}
}
