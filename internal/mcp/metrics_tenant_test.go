package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// /metrics is public. A tenant upstream must not appear in it, neither by name
// nor by a per-server key derived from its uuid (#18).
func TestTenantUpstreamsAreNotInPublicMetrics(t *testing.T) {
	agg := NewAggregatorWithSSRF(NewPool(10, 5, time.Minute), nil, nil)
	tenant := db.MCPServer{UUID: "7a3c0000-0000-4000-8000-00000000ab12", Name: "tenant-secret-name", TenantManaged: true}
	agg.recordCall(tenant)
	sum := sha256.Sum256([]byte(tenant.UUID))
	key := "upstream_" + hex.EncodeToString(sum[:6])

	rr := httptest.NewRecorder()
	agg.metrics.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	body := rr.Body.String()
	if strings.Contains(body, key) || strings.Contains(body, "tenant-secret-name") {
		t.Fatalf("public /metrics exposes a tenant upstream: %s", body)
	}
	// Operator upstreams keep their counters (hashed keys, no names).
	op := db.MCPServer{UUID: "00000000-0000-4000-8000-0000000000cc", Name: "operator-name"}
	agg.recordCall(op)
	rr = httptest.NewRecorder()
	agg.metrics.Handler().ServeHTTP(rr, httptest.NewRequest("GET", "/metrics", nil))
	if strings.Contains(rr.Body.String(), "operator-name") {
		t.Fatal("metrics must never carry server names")
	}
}
