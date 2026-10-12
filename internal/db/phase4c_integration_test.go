package db

// SaaS phase 4c (N5): the header writes are compare-and-set on the database, so
// a stale writer gets a conflict instead of overwriting a newer value. Runs only
// with SUBMCP_TEST_PG_HOST set (see tenant_servers_integration_test.go).

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestIntegrationHeaderWritesAreCompareAndSet(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	uid, ns := seedTenant(t, p, "cas", "trialing", nil)
	srv := &MCPServer{Name: "cas-row", Type: ServerTypeStreamableHTTP,
		URL: strPtr("https://cas.example-zone.net/mcp"), Headers: json.RawMessage(`{"X-Key":"enc:v2:AAAA"}`)}
	if err := p.CreateTenantServer(ctx, uid, ns, srv, 10); err != nil {
		t.Fatal(err)
	}
	original := json.RawMessage(`{"X-Key":"enc:v2:AAAA"}`)

	// The current value is replaced.
	if err := p.SetTenantHeaders(ctx, srv.UUID, original, json.RawMessage(`{"X-Key":"enc:v2:BBBB"}`)); err != nil {
		t.Fatalf("write against the current value: %v", err)
	}
	// A writer holding the original value is now stale: refused, nothing changed.
	err := p.SetTenantHeaders(ctx, srv.UUID, original, json.RawMessage(`{"X-Key":"enc:v2:CCCC"}`))
	if !errors.Is(err, ErrTenantHeadersChanged) {
		t.Fatalf("stale write: err = %v, want ErrTenantHeadersChanged", err)
	}
	got, err := p.GetServer(ctx, srv.UUID, &uid)
	if err != nil || got == nil {
		t.Fatalf("read back: %v", err)
	}
	if !strings.Contains(string(got.Headers), "enc:v2:BBBB") {
		t.Fatalf("stale write changed the row: %s", got.Headers)
	}
	// A missing row is reported as missing, not as a conflict.
	if err := p.SetTenantHeaders(ctx, "00000000-0000-4000-8000-0000000000ff", original, original); !errors.Is(err, ErrTenantServerNotFound) {
		t.Fatalf("missing row: err = %v", err)
	}

	// The same guard on the PATCH write: a stale expected value conflicts and a
	// current one lands.
	edit := *got
	edit.Name = "cas-renamed"
	edit.Headers = json.RawMessage(`{"X-Key":"enc:v2:DDDD"}`)
	ok, err := p.UpdateTenantServer(ctx, uid, &edit, original)
	if ok || !errors.Is(err, ErrTenantHeadersChanged) {
		t.Fatalf("stale PATCH: ok=%v err=%v, want ErrTenantHeadersChanged", ok, err)
	}
	ok, err = p.UpdateTenantServer(ctx, uid, &edit, got.Headers)
	if err != nil || !ok {
		t.Fatalf("current PATCH: ok=%v err=%v", ok, err)
	}
}
