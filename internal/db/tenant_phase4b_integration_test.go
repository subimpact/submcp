package db

import (
	"context"
	"encoding/json"
	"testing"
)

// SaaS phase 4b integration tests (SQL). Same gate as the other integration
// tests: they run only when SUBMCP_TEST_PG_HOST is set.

func TestIntegrationPublicStatsExcludeTenantRows(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	uid, ns := seedTenant(t, p, "pubst", "trialing", nil)

	tenantSrv := &MCPServer{Name: "pub-tenant-" + uid[:8], Type: ServerTypeStreamableHTTP,
		URL: strPtr("https://tenant-pub.example-zone.net/mcp"), Headers: json.RawMessage(`{}`)}
	if err := p.CreateTenantServer(ctx, uid, ns, tenantSrv, 10); err != nil {
		t.Fatal(err)
	}
	if err := p.SyncTools(ctx, tenantSrv.UUID, []SyncToolInput{{Name: "tt", InputSchema: json.RawMessage(`{}`)}}); err != nil {
		t.Fatal(err)
	}
	op, err := p.ListOperatorServers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range op {
		if s.UUID == tenantSrv.UUID || s.TenantManaged {
			t.Fatalf("ListOperatorServers returned a tenant row: %s", s.Name)
		}
	}
	// The operator count must not include the tenant's tool.
	before, err := p.CountOperatorTools(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var tenantTools int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM tools WHERE mcp_server_uuid = $1::uuid`, tenantSrv.UUID).Scan(&tenantTools); err != nil {
		t.Fatal(err)
	}
	if tenantTools == 0 {
		t.Fatal("setup: the tenant server should have a tool")
	}
	var all int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM tools`).Scan(&all); err != nil {
		t.Fatal(err)
	}
	if before > all-tenantTools {
		t.Fatalf("operator tool count %d includes tenant tools (all=%d, tenant=%d)", before, all, tenantTools)
	}
}

func TestIntegrationSetServerCheckOnlyWritesTenantRows(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	var opUUID string
	if err := p.QueryRow(ctx, `INSERT INTO mcp_servers (name, type, url, user_id, tenant_managed)
		VALUES ('it-operator-check', 'STREAMABLE_HTTP', 'https://op.example-zone.net/mcp', NULL, false) RETURNING uuid::text`).Scan(&opUUID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = p.Exec(ctx, `DELETE FROM mcp_servers WHERE uuid = $1::uuid`, opUUID) })
	msg := "boom"
	if err := p.SetServerCheck(ctx, opUUID, &msg); err != nil {
		t.Fatal(err)
	}
	var checked *string
	if err := p.QueryRow(ctx, `SELECT last_error FROM mcp_servers WHERE uuid = $1::uuid`, opUUID).Scan(&checked); err != nil {
		t.Fatal(err)
	}
	if checked != nil {
		t.Fatal("SetServerCheck wrote an operator row (must match tenant_managed = true)")
	}
}

func TestIntegrationCreateTenantServerHonoursChosenUUID(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	uid, ns := seedTenant(t, p, "uuidt", "trialing", nil)
	const chosen = "3f9a2c10-1111-4222-8333-444455556666"
	srv := &MCPServer{UUID: chosen, Name: "chosen-uuid", Type: ServerTypeStreamableHTTP,
		URL: strPtr("https://chosen.example-zone.net/mcp"), Headers: json.RawMessage(`{}`)}
	if err := p.CreateTenantServer(ctx, uid, ns, srv, 10); err != nil {
		t.Fatal(err)
	}
	if srv.UUID != chosen {
		t.Fatalf("the row uuid %s differs from the one the credentials were sealed to (%s)", srv.UUID, chosen)
	}
}

func TestIntegrationLegacyHeaderScanAndRewrite(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	uid, ns := seedTenant(t, p, "legacy", "trialing", nil)
	srv := &MCPServer{Name: "legacy-row", Type: ServerTypeStreamableHTTP, URL: strPtr("https://legacy.example-zone.net/mcp"),
		Headers: json.RawMessage(`{"Authorization":"enc:v1:AAAA"}`)}
	if err := p.CreateTenantServer(ctx, uid, ns, srv, 10); err != nil {
		t.Fatal(err)
	}
	rows, err := p.ListLegacyTenantHeaders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.ServerUUID == srv.UUID {
			found = true
			if r.OwnerUserID != uid {
				t.Fatalf("owner = %s, want %s", r.OwnerUserID, uid)
			}
		}
	}
	if !found {
		t.Fatal("the legacy row was not listed")
	}
	if err := p.SetTenantHeaders(ctx, srv.UUID, json.RawMessage(`{"Authorization":"enc:v2:BBBB"}`)); err != nil {
		t.Fatal(err)
	}
	rows, err = p.ListLegacyTenantHeaders(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ServerUUID == srv.UUID {
			t.Fatal("a rewritten row is still listed as legacy")
		}
	}
}

func strPtr(s string) *string { return &s }
