package db

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Integration tests for the tenant SQL. They need a scratch Postgres (never the
// production database) and are skipped unless SUBMCP_TEST_PG_HOST is set:
//
//	SUBMCP_TEST_PG_HOST, _PORT, _USER, _PASSWORD, _DB (a database you can
//	create tables in; the base schema is loaded by the test runner).
func integrationPool(t *testing.T) *Pool {
	t.Helper()
	host := os.Getenv("SUBMCP_TEST_PG_HOST")
	if host == "" {
		t.Skip("SUBMCP_TEST_PG_HOST not set; skipping tenant database integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := Connect(ctx, host, os.Getenv("SUBMCP_TEST_PG_PORT"), os.Getenv("SUBMCP_TEST_PG_USER"),
		os.Getenv("SUBMCP_TEST_PG_PASSWORD"), os.Getenv("SUBMCP_TEST_PG_DB"), "disable")
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(p.Close)
	if err := p.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return p
}

// seedTenant creates a user, its tenant row and its "all" endpoint/namespace,
// the same shape signup produces. The suffix keeps runs apart.
func seedTenant(t *testing.T, p *Pool, label string, status string, pastDueSince *time.Time) (userID, nsUUID string) {
	t.Helper()
	ctx := context.Background()
	suffix := fmt.Sprintf("%s%d", label, time.Now().UnixNano())
	userID = "it" + strings.ReplaceAll(suffix, "-", "")
	slug := "it" + strings.ToLower(label) + fmt.Sprint(time.Now().UnixNano()%1000000)
	if _, err := p.Exec(ctx, `INSERT INTO users (id, name, email, email_verified) VALUES ($1, $2, $3, true)`,
		userID, label, userID+"@it.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO tenants (user_id, slug, status, past_due_since) VALUES ($1, $2, $3, $4)`,
		userID, slug, status, pastDueSince); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, `INSERT INTO namespaces (name, user_id) VALUES ('all', $1) RETURNING uuid::text`,
		userID).Scan(&nsUUID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO endpoints (name, namespace_uuid, enable_api_key_auth, use_query_param_auth, user_id)
		VALUES ('all', $1, true, false, $2)`, nsUUID, userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { deleteUser(p, userID) })
	return userID, nsUUID
}

// deleteUser removes a test user. Tenants have no FK, so they go explicitly.
func deleteUser(p *Pool, userID string) {
	ctx := context.Background()
	_, _ = p.Exec(ctx, `DELETE FROM tenants WHERE user_id = $1`, userID)
	_, _ = p.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
}

func TestIntegrationTenantServerLifecycle(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	uid, ns := seedTenant(t, p, "lifea", "trialing", nil)
	other, otherNS := seedTenant(t, p, "lifeb", "trialing", nil)
	_ = otherNS

	mk := func(name string) *MCPServer {
		u := "https://" + name + ".example-zone.net/mcp"
		return &MCPServer{Name: name, Type: ServerTypeStreamableHTTP, URL: &u, Headers: []byte(`{"Authorization":"enc:v1:x"}`)}
	}

	// Create: mapped into the tenant namespace, owned by the tenant.
	first := mk("alpha")
	if err := p.CreateTenantServer(ctx, uid, ns, first, 2); err != nil {
		t.Fatalf("create: %v", err)
	}
	if !first.TenantManaged || first.UserID == nil || *first.UserID != uid {
		t.Fatalf("created row = %+v", first)
	}
	var mapped int
	if err := p.QueryRow(ctx, `SELECT count(*) FROM namespace_server_mappings
		WHERE namespace_uuid = $1::uuid AND mcp_server_uuid = $2::uuid AND status = 'ACTIVE'`,
		ns, first.UUID).Scan(&mapped); err != nil || mapped != 1 {
		t.Fatalf("namespace mapping count = %d (%v)", mapped, err)
	}

	// Duplicate name and the per-tenant limit.
	if err := p.CreateTenantServer(ctx, uid, ns, mk("alpha"), 2); err != ErrTenantNameTaken {
		t.Fatalf("duplicate name err = %v", err)
	}
	if err := p.CreateTenantServer(ctx, uid, ns, mk("beta"), 2); err != nil {
		t.Fatalf("second create: %v", err)
	}
	if err := p.CreateTenantServer(ctx, uid, ns, mk("gamma"), 2); err != ErrTenantServerLimit {
		t.Fatalf("limit err = %v", err)
	}
	// The other tenant's quota and names are independent.
	if err := p.CreateTenantServer(ctx, other, otherNS, mk("alpha"), 2); err != nil {
		t.Fatalf("other tenant same name: %v", err)
	}

	rows, err := p.ListTenantServers(ctx, uid)
	if err != nil || len(rows) != 2 {
		t.Fatalf("list = %d rows (%v)", len(rows), err)
	}

	// Tools: discovered tools are counted, listed with status, and toggled.
	desc := "d"
	if err := p.SyncTools(ctx, first.UUID, []SyncToolInput{{Name: "echo", Description: desc, InputSchema: []byte(`{"type":"object"}`)}, {Name: "add", Description: desc, InputSchema: []byte(`{"type":"object"}`)}}); err != nil {
		t.Fatalf("sync: %v", err)
	}
	rows, _ = p.ListTenantServers(ctx, uid)
	if rows[0].ToolCount != 2 {
		t.Fatalf("tool count = %d, want 2", rows[0].ToolCount)
	}
	tools, err := p.ListTenantTools(ctx, uid, ns)
	if err != nil || len(tools) != 2 || tools[0].Status != ServerStatusActive {
		t.Fatalf("tools = %+v (%v)", tools, err)
	}
	if err := p.SetToolMappingStatus(ctx, ns, tools[0].ToolUUID, first.UUID, ServerStatusInactive); err != nil {
		t.Fatalf("disable: %v", err)
	}
	tools, _ = p.ListTenantTools(ctx, uid, ns)
	if tools[0].Status != ServerStatusInactive {
		t.Fatalf("status after disable = %s", tools[0].Status)
	}
	if got, err := p.GetTenantTool(ctx, other, tools[0].ToolUUID, otherNS); err != nil || got != nil {
		t.Fatalf("other tenant reads the tool: %+v (%v)", got, err)
	}
	if got, err := p.GetTenantTool(ctx, uid, tools[0].ToolUUID, ns); err != nil || got == nil {
		t.Fatalf("owner cannot read its tool: %v", err)
	}

	// Check results: recorded, then cleared.
	msg := "upstream said no"
	if err := p.SetServerCheck(ctx, first.UUID, &msg); err != nil {
		t.Fatal(err)
	}
	got, _ := p.GetServer(ctx, first.UUID, &uid)
	if got.LastError == nil || *got.LastError != msg || got.LastCheckedAt == nil {
		t.Fatalf("check not recorded: %+v", got)
	}
	if err := p.SetServerCheck(ctx, first.UUID, nil); err != nil {
		t.Fatal(err)
	}
	got, _ = p.GetServer(ctx, first.UUID, &uid)
	if got.LastError != nil {
		t.Fatal("successful check must clear last_error")
	}

	// Update: owner only; a change clears the check and the quarantine.
	first.Name = "alpha-renamed"
	if ok, err := p.UpdateTenantServer(ctx, other, first); err != nil || ok {
		t.Fatalf("other tenant updated the server: %v %v", ok, err)
	}
	if ok, err := p.UpdateTenantServer(ctx, uid, first); err != nil || !ok {
		t.Fatalf("owner update: %v %v", ok, err)
	}
	if got, _ := p.GetServer(ctx, first.UUID, &uid); got.Name != "alpha-renamed" || got.LastCheckedAt != nil {
		t.Fatalf("update not applied: %+v", got)
	}

	// Operator/NULL-owner isolation: a row not owned by uid is invisible.
	if got, _ := p.GetServer(ctx, first.UUID, &other); got != nil {
		t.Fatal("another tenant can read the server by id")
	}

	// Delete: owner only; tools and mappings cascade away.
	if ok, _ := p.DeleteTenantServer(ctx, other, first.UUID); ok {
		t.Fatal("other tenant deleted the server")
	}
	if ok, err := p.DeleteTenantServer(ctx, uid, first.UUID); err != nil || !ok {
		t.Fatalf("owner delete: %v %v", ok, err)
	}
	var left int
	_ = p.QueryRow(ctx, `SELECT count(*) FROM tools WHERE mcp_server_uuid = $1::uuid`, first.UUID).Scan(&left)
	if left != 0 {
		t.Fatalf("tools left after delete: %d", left)
	}
	_ = p.QueryRow(ctx, `SELECT count(*) FROM namespace_tool_mappings WHERE mcp_server_uuid = $1::uuid`, first.UUID).Scan(&left)
	if left != 0 {
		t.Fatalf("tool mappings left after delete: %d", left)
	}
	_ = p.QueryRow(ctx, `SELECT count(*) FROM namespace_server_mappings WHERE mcp_server_uuid = $1::uuid`, first.UUID).Scan(&left)
	if left != 0 {
		t.Fatalf("server mappings left after delete: %d", left)
	}
}

func TestIntegrationPastDueGraceIsAnchoredOnPastDueSince(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	fresh := time.Now().Add(-24 * time.Hour)
	old := time.Now().Add(-4 * 24 * time.Hour)

	uidFresh, _ := seedTenant(t, p, "pdfresh", "past_due", &fresh)
	uidOld, _ := seedTenant(t, p, "pdold", "past_due", &old)

	tf, err := p.GetTenantByUserID(ctx, uidFresh)
	if err != nil || tf == nil || tf.PastDueSince == nil {
		t.Fatalf("fresh tenant read: %+v (%v)", tf, err)
	}
	if e := EvaluateEntitlement(tf, time.Now()); e.Denied {
		t.Fatalf("1 day into past_due must be allowed: %s", e.Reason)
	}
	to, _ := p.GetTenantByUserID(ctx, uidOld)
	if e := EvaluateEntitlement(to, time.Now()); !e.Denied || e.Reason != "payment_overdue" {
		t.Fatalf("4 days into past_due must be denied: %+v", e)
	}
}

func TestIntegrationPastDueMigrationIsIdempotentAndBackfills(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	uid, _ := seedTenant(t, p, "pdmig", "past_due", nil) // past_due with no since: legacy row

	sql, err := migrationsFS.ReadFile("migrations/0005_tenant_past_due_since.sql")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // run twice: the second run must change nothing
		if _, err := p.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	tn, _ := p.GetTenantByUserID(ctx, uid)
	if tn.PastDueSince == nil {
		t.Fatal("legacy past_due tenant was not backfilled")
	}
}

func TestIntegrationBackfillLeavesOtherStatusesAlone(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	uid, _ := seedTenant(t, p, "active", "active", nil)
	if _, err := p.Exec(ctx, `UPDATE tenants SET past_due_since = now() WHERE user_id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	// The backfill only touches past_due rows, so an active tenant keeps its state.
	sql, _ := migrationsFS.ReadFile("migrations/0005_tenant_past_due_since.sql")
	if _, err := p.Exec(ctx, string(sql)); err != nil {
		t.Fatal(err)
	}
	tn, _ := p.GetTenantByUserID(ctx, uid)
	if tn.Status != TenantActive {
		t.Fatalf("status changed to %s", tn.Status)
	}
}

// A legacy (operator-style) upstream can share an owner with a tenant API key:
// the operator's own non-admin keys are bound to the operator user, and so are
// the operator's rows. The tenant API must not list, change, delete or test
// such a row, or a non-admin key could turn an operator upstream into a tenant
// row (which changes its network policy and breaks it).
func TestIntegrationTenantAPIIgnoresLegacyRows(t *testing.T) {
	p := integrationPool(t)
	ctx := context.Background()
	uid, ns := seedTenant(t, p, "legacy", "active", nil)

	legacyURL := "https://legacy.example-zone.net/mcp"
	var legacyID string
	if err := p.QueryRow(ctx, `
		INSERT INTO mcp_servers (name, type, url, headers, user_id)
		VALUES ('opsrv', 'STREAMABLE_HTTP', $1, '{"Authorization":"Bearer legacy-plain-1234"}', $2)
		RETURNING uuid::text`, legacyURL, uid).Scan(&legacyID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `INSERT INTO namespace_server_mappings (namespace_uuid, mcp_server_uuid, status)
		VALUES ($1, $2, 'ACTIVE')`, ns, legacyID); err != nil {
		t.Fatal(err)
	}

	rows, err := p.ListTenantServers(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Server.UUID == legacyID {
			t.Fatal("tenant API lists a legacy row")
		}
	}

	hijack := "https://hijack.example-zone.net/mcp"
	ok, err := p.UpdateTenantServer(ctx, uid, &MCPServer{UUID: legacyID, Name: "opsrv", Type: ServerTypeStreamableHTTP,
		URL: &hijack, Headers: []byte(`{}`)})
	if err != nil || ok {
		t.Fatalf("tenant API rewrote a legacy row: updated=%v err=%v", ok, err)
	}
	if deleted, _ := p.DeleteTenantServer(ctx, uid, legacyID); deleted {
		t.Fatal("tenant API deleted a legacy row")
	}

	var url string
	var managed bool
	if err := p.QueryRow(ctx, `SELECT url, tenant_managed FROM mcp_servers WHERE uuid = $1::uuid`, legacyID).Scan(&url, &managed); err != nil {
		t.Fatal(err)
	}
	if url != legacyURL || managed {
		t.Fatalf("legacy row changed: url=%s tenant_managed=%v", url, managed)
	}
}
