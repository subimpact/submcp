package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/db"
	"github.com/subimpact/submcp/internal/httpapi"
	"github.com/subimpact/submcp/internal/mcp"
	"github.com/subimpact/submcp/internal/ui"
)

// tenantRouteServer wires the tenant API the way cmd/submcp does, with
// tenant mode and a service token, over the fakes from golden_test.go.
func tenantRouteServer(t *testing.T) *mcp.Server {
	t.Helper()
	pool := mcp.NewPool(10, 5, time.Minute)
	agg := mcp.NewAggregator(pool, &fakeToolStore{})
	agg.SetTenantUpstreams(nil, mcp.DefaultTenantNetPolicy())
	keys := map[string]*db.APIKey{
		"sk_sub_routes-tenant-key": {UUID: "k1", Name: "default", UserID: strp("tenant-owner-0001")},
	}
	srv := mcp.NewServer(&fakeEndpointStore{endpoints: map[string]*db.Endpoint{}}, agg, pool,
		mcp.NewAuth(&fakeKeyDB{keys: keys}), time.Hour)
	srv.EnableTenants(&routeTenantStore{}, "mcp.routes-fixture.net", 0)
	if err := srv.EnableTenantAPI(&routeTenantStore{}, mcp.TenantAPIConfig{
		ServiceToken: "routes-service-token-0123456789abcdef0123",
	}); err != nil {
		t.Fatal(err)
	}
	return srv
}

func strp(s string) *string { return &s }

// routeTenantStore answers only what the auth path reads (tenant lookup).
type routeTenantStore struct{ mcp.TenantServerStore }

func (routeTenantStore) GetTenantByUserID(_ context.Context, uid string) (*db.Tenant, error) {
	if uid == "tenant-owner-0001" {
		return &db.Tenant{ID: "t1", UserID: uid, Slug: "routes", Status: db.TenantActive}, nil
	}
	return nil, nil
}

func (routeTenantStore) GetTenantBySlug(_ context.Context, slug string) (*db.Tenant, error) {
	return nil, nil
}

// ListTenantServers is reached only after a successful tenant auth.
func (routeTenantStore) ListTenantServers(context.Context, string) ([]db.TenantServerRow, error) {
	return nil, nil
}

func (routeTenantStore) Entitlement(_ context.Context, t *db.Tenant) (*db.TenantEntitlement, error) {
	return db.EvaluateEntitlement(t, time.Now()), nil
}

func (routeTenantStore) UsageToday(_ context.Context, _ string) (int64, error) { return 0, nil }
func (routeTenantStore) BumpUsage(_ context.Context, _ string) error           { return nil }
func (routeTenantStore) TryBumpUsage(_ context.Context, _ string, _ int64) (bool, error) {
	return true, nil
}

func TestTenantAPIIsMountedOnThePublicListener(t *testing.T) {
	srv := tenantRouteServer(t)
	h := httpapi.Build(slog.New(slog.NewTextHandler(io.Discard, nil)), srv, ui.New(&fakeUIStore{}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	// No key: the tenant API answers, with its own JSON error (not the admin UI).
	resp, err := http.Get(ts.URL + "/api/tenant/servers")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil || body["error"] != "authentication_required" {
		t.Fatalf("body = %v (%v)", body, err)
	}

	// The service headers do not open the public listener.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/tenant/servers", nil)
	req.Header.Set("X-Submcp-Service-Token", "routes-service-token-0123456789abcdef0123")
	req.Header.Set("X-Submcp-Tenant-User", "tenant-owner-0001")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("service headers on the public listener = %d, want 401", resp2.StatusCode)
	}

	// A valid tenant key reaches the API.
	req3, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/tenant/servers", nil)
	req3.Header.Set("X-API-Key", "sk_sub_routes-tenant-key")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("tenant key = %d, want 200", resp3.StatusCode)
	}
}

func TestInternalListenerServesOnlyServiceAuth(t *testing.T) {
	srv := tenantRouteServer(t)
	h := httpapi.BuildInternal(slog.New(slog.NewTextHandler(io.Discard, nil)), srv)
	ts := httptest.NewServer(h)
	defer ts.Close()

	// Tenant key alone is not service auth on the internal listener.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/tenant/servers", nil)
	req.Header.Set("X-API-Key", "sk_sub_routes-tenant-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("API key on the internal listener = %d, want 401", resp.StatusCode)
	}

	// Service auth works, and nothing else is served there.
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/tenant/servers", nil)
	req2.Header.Set("X-Submcp-Service-Token", "routes-service-token-0123456789abcdef0123")
	req2.Header.Set("X-Submcp-Tenant-User", "tenant-owner-0001")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp2.Body)
		t.Fatalf("service auth = %d (%s), want 200", resp2.StatusCode, strings.TrimSpace(string(raw)))
	}

	for _, path := range []string{"/api/admin/overview", "/metamcp/all/mcp", "/health"} {
		r, _ := http.Get(ts.URL + path)
		if r != nil {
			r.Body.Close()
			if r.StatusCode != http.StatusNotFound {
				t.Fatalf("%s on the internal listener = %d, want 404", path, r.StatusCode)
			}
		}
	}
}
