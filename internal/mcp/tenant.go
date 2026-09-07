package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// TenantStore is the DB surface the gateway needs for tenant entitlement
// and usage caps (SaaS Phase 1). Optional — when unset the gateway runs in
// legacy single-tenant mode.
type TenantStore interface {
	GetTenantByUserID(ctx context.Context, userID string) (*db.Tenant, error)
	GetTenantBySlug(ctx context.Context, slug string) (*db.Tenant, error)
	Entitlement(ctx context.Context, t *db.Tenant) (*db.TenantEntitlement, error)
	UsageToday(ctx context.Context, tenantID string) (int64, error)
	BumpUsage(ctx context.Context, tenantID string) error
}

// tenantGate enforces per-tenant entitlement + trial usage caps before MCP
// requests are served.
type tenantGate struct {
	store         TenantStore
	baseHost      string // e.g. "mcp.subimpact.net"; "" = disabled
	trialDailyCap int64  // daily tool-call cap while trialing; 0 = no cap
}

// checkEntitlement denies the request when the tenant is not entitled.
// Returns true when the request may proceed.
func (g *tenantGate) checkEntitlement(w http.ResponseWriter, r *http.Request, t *db.Tenant) bool {
	if t == nil {
		return true
	}
	e, err := g.store.Entitlement(r.Context(), t)
	if err != nil || e == nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Entitlement check failed")
		return false
	}
	if e.Denied {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             e.Reason,
			"error_description": "Your subscription or trial has ended. Subscribe to keep using your gateway.",
			"url":               "https://app.subimpact.net/billing",
			"timestamp":         time.Now().UTC().Format(time.RFC3339),
		})
		return false
	}
	return true
}

// allowToolCall enforces the trial usage cap for tools/call.
// Returns true when the call may proceed; false writes the 429.
func (g *tenantGate) allowToolCall(w http.ResponseWriter, r *http.Request, t *db.Tenant) bool {
	if g == nil || g.store == nil || t == nil || g.trialDailyCap <= 0 {
		return true
	}
	// Only trialing tenants are capped; paid (active) tenants are not.
	if t.Status != db.TenantTrialing {
		return true
	}
	used, err := g.store.UsageToday(r.Context(), t.ID)
	if err != nil {
		// Fail-open on DB errors for usage accounting (availability over
		// strictness); the entitlement gate already passed.
		return true
	}
	if used >= g.trialDailyCap {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]any{
			"error":             "trial_limit_reached",
			"error_description": "You've reached the daily trial limit. Subscribe to continue using your gateway.",
			"url":               "https://app.subimpact.net/billing",
			"timestamp":         time.Now().UTC().Format(time.RFC3339),
		})
		return false
	}
	return true
}

// bumpToolCall records a successful tool call against the tenant's daily
// counter. Errors are ignored (usage accounting must never break a call).
func (g *tenantGate) bumpToolCall(ctx context.Context, t *db.Tenant) {
	if g == nil || g.store == nil || t == nil {
		return
	}
	_ = g.store.BumpUsage(ctx, t.ID)
}

// subdomainSlug extracts the tenant slug from a request Host.
// Returns "" when the host is not a tenant subdomain (bare base host).
func subdomainSlug(host, baseHost string) string {
	if baseHost == "" || host == "" {
		return ""
	}
	host = strings.TrimSpace(host)
	// Strip port (Host may be "slug.mcp.subimpact.net:443" behind proxies).
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if host == baseHost || host == "www."+baseHost {
		return ""
	}
	if strings.HasSuffix(host, "."+baseHost) {
		return strings.TrimSuffix(host, "."+baseHost)
	}
	return ""
}
