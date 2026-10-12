package ui

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/subimpact/submcp/internal/db"
)

// statsStore holds one operator and one tenant upstream. ListServers and
// CountTools are the all-rows queries (the phase 4 handler used them); the
// Operator* methods are the queries the public stats must use.
type statsStore struct {
	*spyStore
}

func (s statsStore) ListServers(context.Context, *string) ([]db.MCPServer, error) {
	return []db.MCPServer{
		{Name: "operator-upstream", Type: db.ServerTypeStreamableHTTP},
		{Name: "tenant-secret-upstream", Type: db.ServerTypeStreamableHTTP, TenantManaged: true},
	}, nil
}

func (s statsStore) ListOperatorServers(context.Context) ([]db.MCPServer, error) {
	return []db.MCPServer{{Name: "operator-upstream", Type: db.ServerTypeStreamableHTTP}}, nil
}

func (s statsStore) CountTools(context.Context) (int, error)              { return 5, nil } // operator 1 + tenant 4
func (s statsStore) CountOperatorTools(context.Context) (int, error)      { return 1, nil }
func (s statsStore) CountNamespaces(context.Context) (int, error)         { return 3, nil }
func (s statsStore) CountOperatorNamespaces(context.Context) (int, error) { return 1, nil }

// PoC1 (public stats): a tenant upstream must not be named, counted or listed
// on the unauthenticated stats endpoint.
func TestPoC1_PublicStatsExcludeTenantUpstreams(t *testing.T) {
	u := NewWithAllowlist(statsStore{&spyStore{}}, "")
	rr := httptest.NewRecorder()
	u.handlePublicStats(rr, httptest.NewRequest("GET", "/api/public/stats", nil))
	body := rr.Body.String()
	if strings.Contains(body, "tenant-secret-upstream") {
		t.Fatalf("public stats name a tenant upstream: %s", body)
	}
	var got struct {
		Servers    int              `json:"servers"`
		Tools      int              `json:"tools"`
		Namespaces int              `json:"namespaces"`
		Upstreams  []map[string]any `json:"upstreams"`
	}
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got.Servers != 1 || len(got.Upstreams) != 1 {
		t.Fatalf("public server count %d and list %d, want 1 operator row only", got.Servers, len(got.Upstreams))
	}
	if got.Tools != 1 {
		t.Fatalf("public tool count %d includes tenant tools; want 1", got.Tools)
	}
	if got.Namespaces != 1 {
		t.Fatalf("public namespace count %d tracks tenant signups; want the operator count 1", got.Namespaces)
	}
}

// The handler skips a tenant row even if a store returns one (defence in depth).
func TestPublicStatsSkipTenantRowsEvenIfReturned(t *testing.T) {
	leaky := &leakyOperatorStore{statsStore: statsStore{&spyStore{}}}
	u := NewWithAllowlist(leaky, "")
	rr := httptest.NewRecorder()
	u.handlePublicStats(rr, httptest.NewRequest("GET", "/api/public/stats", nil))
	if strings.Contains(rr.Body.String(), "tenant-secret-upstream") {
		t.Fatalf("a tenant row reached the public payload: %s", rr.Body.String())
	}
}

type leakyOperatorStore struct{ statsStore }

func (l *leakyOperatorStore) ListOperatorServers(context.Context) ([]db.MCPServer, error) {
	return l.ListServers(context.Background(), nil)
}
