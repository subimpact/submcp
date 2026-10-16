package httpapi_test

import (
	"context"
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

// blockServer wires a server the way cmd/submcp does, with tenant mode on and
// the production base host.
func blockServer(t *testing.T) *mcp.Server {
	t.Helper()
	pool := mcp.NewPool(10, 5, time.Minute)
	agg := mcp.NewAggregator(pool, &fakeToolStore{})
	srv := mcp.NewServer(&fakeEndpointStore{endpoints: map[string]*db.Endpoint{}}, agg, pool,
		mcp.NewAuth(&fakeKeyDB{keys: map[string]*db.APIKey{}}), time.Hour)
	srv.EnableTenants(&blockTenantStore{}, "mcp.subimpact.net", 0)
	return srv
}

type blockTenantStore struct{ mcp.TenantServerStore }

func (blockTenantStore) GetTenantByUserID(context.Context, string) (*db.Tenant, error) {
	return nil, nil
}

func (blockTenantStore) GetTenantBySlug(context.Context, string) (*db.Tenant, error) {
	return nil, nil
}

func (blockTenantStore) Entitlement(_ context.Context, t *db.Tenant) (*db.TenantEntitlement, error) {
	return db.EvaluateEntitlement(t, time.Now()), nil
}

func (blockTenantStore) UsageToday(context.Context, string) (int64, error) { return 0, nil }
func (blockTenantStore) BumpUsage(context.Context, string) error           { return nil }
func (blockTenantStore) TryBumpUsage(context.Context, string, int64) (bool, error) {
	return true, nil
}

// noProxyClient talks to ts.URL directly (no env proxy) and stops at the first
// response, so redirect responses are inspected, not followed.
var noProxyClient = &http.Client{
	Transport:     &http.Transport{Proxy: nil},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

func doWithHost(t *testing.T, ts *httptest.Server, method, target, host, body string) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r, err := http.NewRequest(method, ts.URL+target, rd)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = host
	resp, err := noProxyClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAdminBlockedOnTenantHosts(t *testing.T) {
	h := httpapi.Build(slog.New(slog.NewTextHandler(io.Discard, nil)), blockServer(t), ui.New(&fakeUIStore{}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	paths := []string{
		"/admin", "/admin/", "/admin/overview", "/ADMIN", "/Admin/Keys",
		"//admin", "/x/../admin", "/%61dmin", "/admin/../admin/keys",
		"/api/admin", "/api/admin/", "/api/admin/keys", "/api/ADMIN/login",
		"/API/admin/overview",
	}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			resp := doWithHost(t, ts, "GET", p, "acme.mcp.subimpact.net", "")
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("%s: status = %d, want 404 (body %s)", p, resp.StatusCode, body)
			}
			if !strings.Contains(string(body), `"not_found"`) {
				t.Fatalf("%s: body = %s, want not_found", p, body)
			}
		})
	}
}

func TestTenantHostStillServesEverythingElse(t *testing.T) {
	h := httpapi.Build(slog.New(slog.NewTextHandler(io.Discard, nil)), blockServer(t), ui.New(&fakeUIStore{}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	// /metamcp/all/mcp and /api/tenant/servers must not be caught by the
	// admin block: the answers come from the gateway routes (JSON / auth
	// errors), never from the block's not_found body.
	r, _ := http.NewRequest("POST", ts.URL+"/metamcp/all/mcp", strings.NewReader("{}"))
	r.Host = "acme.mcp.subimpact.net"
	resp, err := noProxyClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.HasPrefix(string(body), `{"error":"not_found","error_description":"There is nothing`) {
		t.Fatalf("/metamcp caught by the admin block on tenant host: %s", body)
	}

	r, _ = http.NewRequest("GET", ts.URL+"/api/tenant/servers", nil)
	r.Host = "acme.mcp.subimpact.net"
	resp, err = noProxyClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if strings.HasPrefix(string(body), `{"error":"not_found","error_description":"There is nothing`) {
		t.Fatalf("/api/tenant caught by the admin block on tenant host: %s", body)
	}

	// /health must still answer on a tenant host.
	r, _ = http.NewRequest("GET", ts.URL+"/health", nil)
	r.Host = "acme.mcp.subimpact.net"
	resp, err = noProxyClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "ok") {
		t.Fatalf("/health on tenant host: %d %s", resp.StatusCode, body)
	}
}

func TestAdminAllowedOnApexAndLocal(t *testing.T) {
	h := httpapi.Build(slog.New(slog.NewTextHandler(io.Discard, nil)), blockServer(t), ui.New(&fakeUIStore{}))
	ts := httptest.NewServer(h)
	defer ts.Close()

	for _, c := range []struct{ host, path string }{
		{"mcp.subimpact.net", "/admin"},
		{"mcp.subimpact.net:443", "/admin/keys"},
		{"127.0.0.1:12008", "/api/admin/login"},
		{"mcp.subimpact.net", "/api/admin/overview"},
		{"localhost:12008", "/admin"},
	} {
		resp := doWithHost(t, ts, "GET", c.path, c.host, "")
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound &&
			strings.Contains(string(body), `"error_description":"There is nothing at this address."`) {
			t.Fatalf("%s on %s: admin block fired on a non-tenant host", c.path, c.host)
		}
	}
}