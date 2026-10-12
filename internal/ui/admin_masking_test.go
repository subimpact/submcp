package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/subimpact/submcp/internal/db"
)

// maskStore serves one server with real headers and records the update the
// admin API would write. It wraps spyStore for everything else.
type maskStore struct {
	*spyStore
	server  db.MCPServer
	updated *db.MCPServer
}

func (m *maskStore) GetServer(_ context.Context, uuid string, _ *string) (*db.MCPServer, error) {
	if uuid == m.server.UUID {
		s := m.server
		return &s, nil
	}
	return nil, nil
}

func (m *maskStore) ListServers(context.Context, *string) ([]db.MCPServer, error) {
	return []db.MCPServer{m.server}, nil
}

func (m *maskStore) UpdateServer(_ context.Context, s *db.MCPServer, _ *string) error {
	cp := *s
	m.updated = &cp
	return nil
}

func newMaskStore(tenantManaged bool) *maskStore {
	return &maskStore{
		spyStore: &spyStore{ownedServers: map[string]*string{"srv-op": strp("op-user")}},
		server: db.MCPServer{
			UUID:          "srv-op",
			Name:          "matrix",
			Type:          db.ServerTypeStreamableHTTP,
			URL:           strp("https://matrix.example-zone.net/mcp"),
			UserID:        strp("op-user"),
			Headers:       json.RawMessage(`{"Authorization":"Bearer matrix-operator-token-ZZ99"}`),
			TenantManaged: tenantManaged,
		},
	}
}

// The admin overview must never carry a header value in full.
func TestAdminOverviewMasksHeaderValues(t *testing.T) {
	m := newMaskStore(false)
	u := New(m)
	req := sessAuth(u, httptest.NewRequest(http.MethodGet, "/api/admin/overview", nil), strp("op-user"))
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("overview = %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if strings.Contains(body, "matrix-operator-token") {
		t.Fatalf("overview leaks the header value: %s", body)
	}
	if !strings.Contains(body, "ZZ99") {
		t.Fatalf("overview should show the last four characters: %s", body)
	}
}

// Saving the admin edit form sends the masked value back: the stored
// credential must survive, and the edited URL must still apply.
func TestAdminPutKeepsStoredCredentialWhenMaskIsReturned(t *testing.T) {
	m := newMaskStore(false)
	u := New(m)
	body := `{"name":"matrix","url":"https://matrix.example-zone.net/mcp2","type":"STREAMABLE_HTTP","headers":{"Authorization":"` + "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" + `ZZ99"}}`
	req := sessAuth(u, httptest.NewRequest(http.MethodPut, "/api/admin/servers/srv-op", strings.NewReader(body)), strp("op-user"))
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("put = %d: %s", rr.Code, rr.Body.String())
	}
	if m.updated == nil {
		t.Fatal("update not written")
	}
	var got map[string]string
	if err := json.Unmarshal(m.updated.Headers, &got); err != nil {
		t.Fatal(err)
	}
	if got["Authorization"] != "Bearer matrix-operator-token-ZZ99" {
		t.Fatalf("stored credential = %q, want the original", got["Authorization"])
	}
}

// A masked value that does not match is refused and nothing is written.
func TestAdminPutRefusesMismatchedMask(t *testing.T) {
	m := newMaskStore(false)
	u := New(m)
	body := `{"name":"matrix","url":"https://matrix.example-zone.net/mcp","headers":{"Authorization":"` + "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" + `0000"}}`
	req := sessAuth(u, httptest.NewRequest(http.MethodPut, "/api/admin/servers/srv-op", strings.NewReader(body)), strp("op-user"))
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest || m.updated != nil {
		t.Fatalf("mismatched mask: status %d, updated=%v", rr.Code, m.updated != nil)
	}
}

// The admin path must not write or test tenant-managed rows: those hold sealed
// credentials that only the tenant API can open.
func TestAdminCannotWriteOrTestTenantRows(t *testing.T) {
	m := newMaskStore(true)
	u := New(m)

	put := sessAuth(u, httptest.NewRequest(http.MethodPut, "/api/admin/servers/srv-op",
		strings.NewReader(`{"name":"x","url":"https://x.example-zone.net/mcp"}`)), strp("op-user"))
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, put)
	if rr.Code != http.StatusConflict || m.updated != nil {
		t.Fatalf("admin PUT of a tenant row: %d (written=%v)", rr.Code, m.updated != nil)
	}

	test := sessAuth(u, httptest.NewRequest(http.MethodPost, "/api/admin/servers/srv-op/test", nil), strp("op-user"))
	rr2 := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr2, test)
	if rr2.Code != http.StatusConflict {
		t.Fatalf("admin test of a tenant row: %d", rr2.Code)
	}
}
