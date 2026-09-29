package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// fakeTenantStore implements TenantStore against an in-memory map.
type fakeTenantStore struct {
	tenants map[string]*db.Tenant // user_id -> tenant
	usage   map[string]int64      // tenant_id -> today's calls
}

func (f *fakeTenantStore) GetTenantByUserID(_ context.Context, userID string) (*db.Tenant, error) {
	return f.tenants[userID], nil
}
func (f *fakeTenantStore) GetTenantBySlug(_ context.Context, slug string) (*db.Tenant, error) {
	for _, t := range f.tenants {
		if t.Slug == slug {
			return t, nil
		}
	}
	return nil, nil
}
func (f *fakeTenantStore) Entitlement(_ context.Context, t *db.Tenant) (*db.TenantEntitlement, error) {
	e := &db.TenantEntitlement{Tenant: t}
	now := time.Now()
	switch t.Status {
	case db.TenantTrialing:
		if t.TrialEndsAt != nil && now.After(*t.TrialEndsAt) {
			e.Denied = true
			e.TrialEnded = true
			e.Reason = "trial_ended"
		}
	case db.TenantPastDue:
		if t.SubscriptionEndsAt == nil || now.Sub(*t.SubscriptionEndsAt) > 7*24*time.Hour {
			e.Denied = true
			e.Reason = "payment_overdue"
		}
	case db.TenantCanceled:
		e.Denied = true
		e.Reason = "subscription_canceled"
	}
	return e, nil
}
func (f *fakeTenantStore) UsageToday(_ context.Context, tenantID string) (int64, error) {
	return f.usage[tenantID], nil
}
func (f *fakeTenantStore) BumpUsage(_ context.Context, tenantID string) error {
	f.usage[tenantID]++
	return nil
}
func (f *fakeTenantStore) TryBumpUsage(_ context.Context, tenantID string, cap int64) (bool, error) {
	if f.usage[tenantID] >= cap {
		return false, nil
	}
	f.usage[tenantID]++
	return true, nil
}

func ten(id, userID, slug, status string, trialEnd time.Time) *db.Tenant {
	t := &db.Tenant{ID: id, UserID: userID, Slug: slug, Status: db.TenantStatus(status), Plan: "pro"}
	if !trialEnd.IsZero() {
		t.TrialEndsAt = &trialEnd
	}
	return t
}

func TestSubdomainSlug(t *testing.T) {
	cases := []struct {
		host, base string
		want       string
	}{
		{"acme.mcp.subimpact.net", "mcp.subimpact.net", "acme"},
		{"mcp.subimpact.net", "mcp.subimpact.net", ""},
		{"www.mcp.subimpact.net", "mcp.subimpact.net", ""},
		{"acme.mcp.subimpact.net:443", "mcp.subimpact.net", "acme"},
		{"other.mcp.subimpact.net", "mcp.subimpact.net", "other"},
		{"foo.example.com", "mcp.subimpact.net", ""},
		{"", "mcp.subimpact.net", ""},
	}
	for _, c := range cases {
		if got := subdomainSlug(c.host, c.base); got != c.want {
			t.Errorf("subdomainSlug(%q, %q) = %q, want %q", c.host, c.base, got, c.want)
		}
	}
}

func TestEntitlementDeniesCanceledAndPastTrial(t *testing.T) {
	now := time.Now()
	g := &tenantGate{
		store: &fakeTenantStore{
			tenants: map[string]*db.Tenant{
				"u1": ten("t1", "u1", "acme", "trialing", now.Add(-time.Hour)), // trial over
				"u2": ten("t2", "u2", "beta", "active", time.Time{}),
				"u3": ten("t3", "u3", "gone", "canceled", time.Time{}),
			},
			usage: map[string]int64{},
		},
		baseHost: "mcp.subimpact.net",
	}

	// Trial over -> denied (402).
	t1, _ := g.store.GetTenantByUserID(context.Background(), "u1")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "https://acme.mcp.subimpact.net/metamcp/all/mcp", nil)
	if g.checkEntitlement(rec, req, t1) {
		t.Fatal("expected denial for expired trial")
	}
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", rec.Code)
	}

	// Active -> allowed.
	t2, _ := g.store.GetTenantByUserID(context.Background(), "u2")
	rec2 := httptest.NewRecorder()
	if !g.checkEntitlement(rec2, req, t2) {
		t.Fatal("expected active tenant to pass")
	}

	// Canceled -> denied.
	t3, _ := g.store.GetTenantByUserID(context.Background(), "u3")
	rec3 := httptest.NewRecorder()
	if g.checkEntitlement(rec3, req, t3) {
		t.Fatal("expected denial for canceled tenant")
	}
	if rec3.Code != http.StatusPaymentRequired {
		t.Fatalf("expected 402, got %d", rec3.Code)
	}
}

func TestTrialUsageCap(t *testing.T) {
	now := time.Now()
	store := &fakeTenantStore{
		tenants: map[string]*db.Tenant{
			"u1": ten("t1", "u1", "acme", "trialing", now.Add(24*time.Hour)),
			"u2": ten("t2", "u2", "beta", "active", time.Time{}),
		},
		usage: map[string]int64{},
	}
	g := &tenantGate{store: store, baseHost: "mcp.subimpact.net", trialDailyCap: 3}

	req := httptest.NewRequest(http.MethodPost, "https://acme.mcp.subimpact.net/metamcp/all/mcp", nil)
	t1, _ := store.GetTenantByUserID(context.Background(), "u1")

	// 3 calls allowed, 4th denied.
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		if !g.allowToolCall(rec, req, t1) {
			t.Fatalf("call %d should be allowed", i+1)
		}
		g.bumpToolCall(req.Context(), t1)
	}
	rec := httptest.NewRecorder()
	if g.allowToolCall(rec, req, t1) {
		t.Fatal("4th call should be denied")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}
	var body map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] != "trial_limit_reached" {
		t.Fatalf("expected trial_limit_reached error, got %v", body["error"])
	}

	// Active (paying) tenants are NOT capped.
	t2, _ := store.GetTenantByUserID(context.Background(), "u2")
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "https://mcp.subimpact.net/metamcp/all/mcp", nil)
	for i := 0; i < 10; i++ {
		if !g.allowToolCall(rec2, req2, t2) {
			t.Fatalf("active tenant call %d should be allowed despite cap", i+1)
		}
		g.bumpToolCall(req2.Context(), t2)
	}
}

func TestResolveTenantHostBinding(t *testing.T) {
	now := time.Now()
	store := &fakeTenantStore{
		tenants: map[string]*db.Tenant{
			"u1": ten("t1", "u1", "acme", "trialing", now.Add(24*time.Hour)),
			"u2": ten("t2", "u2", "other", "active", time.Time{}),
		},
		usage: map[string]int64{},
	}
	s := &Server{tenants: &tenantGate{store: store, baseHost: "mcp.subimpact.net", trialDailyCap: 100}}
	ep := &db.Endpoint{UUID: "ep1", Name: "all", UserID: strptr("u1")}

	// Correct host -> tenant resolved by slug, ownership verified.
	req := httptest.NewRequest(http.MethodPost, "https://acme.mcp.subimpact.net/metamcp/all/mcp", nil)
	tnt, err := s.resolveTenantByOwner(req, ep)
	if err != nil {
		t.Fatalf("resolveTenantByOwner: %v", err)
	}
	if tnt == nil || tnt.Slug != "acme" {
		t.Fatalf("expected acme tenant, got %+v", tnt)
	}

	// Legacy mode (no gate) -> no tenant, no error.
	s2 := &Server{}
	req4 := httptest.NewRequest(http.MethodPost, "https://anything.example.com/metamcp/all/mcp", nil)
	tnt2, err := s2.resolveTenantByOwner(req4, ep)
	if err != nil || tnt2 != nil {
		t.Fatalf("legacy mode should return nil, nil; got %+v, %v", tnt2, err)
	}
}

func strptr(s string) *string { return &s }
