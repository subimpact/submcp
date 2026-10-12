package mcp

// SaaS phase 4c regressions for tenant credentials (N5): runtime dual-read,
// writes always v2, and a compare-and-set that returns 409 instead of silently
// overwriting a concurrent change.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// Every write is v2, whatever the input.
func TestN5WritesAreAlwaysV2(t *testing.T) {
	box := testBox(t)
	raw, err := SealHeaders(map[string]string{"Authorization": "Bearer write-check-1234"}, box, testOwner, testServerUUID)
	if err != nil {
		t.Fatal(err)
	}
	var stored map[string]string
	if err := json.Unmarshal(raw, &stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored["Authorization"], sealPrefix) {
		t.Fatalf("a write must be v2, got %q", stored["Authorization"][:12])
	}
}

// N5 (409): a PATCH that read the row before a concurrent header write must not
// revert it. The write is refused with 409 conflict, so the client reloads.
func TestN5ConcurrentHeaderChangeReturns409(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "cas", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"X-Api-Key": "first-value-AAAA"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)

	// Another request rewrites the headers between this PATCH's read and write.
	fx.db.beforeUpdate = func() {
		fx.db.mu.Lock()
		defer fx.db.mu.Unlock()
		fx.db.servers[id].Headers = json.RawMessage(`{"X-Api-Key":"concurrent-value-BBBB"}`)
	}
	defer func() { fx.db.beforeUpdate = nil }()

	rr = fx.api(keyA, "PATCH", "/api/tenant/servers/"+id, map[string]any{"name": "cas-renamed"})
	if rr.Code != http.StatusConflict {
		t.Fatalf("a PATCH over a concurrent write must be 409, got %d %s", rr.Code, rr.Body.String())
	}
	if code := errCode(t, rr); code != "conflict" {
		t.Fatalf("error code = %q, want conflict", code)
	}
	// The concurrent write survived: the name-only PATCH did not revert it.
	if got := string(fx.db.servers[id].Headers); !strings.Contains(got, "concurrent-value-BBBB") {
		t.Fatalf("the concurrent header write was reverted: %s", got)
	}
}

// Without a concurrent write the same PATCH succeeds (the CAS is not a lock).
func TestN5UncontendedPatchSucceeds(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "cas-ok", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"X-Api-Key": "first-value-CCCC"},
	})
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)
	rr = fx.api(keyA, "PATCH", "/api/tenant/servers/"+id, map[string]any{"name": "cas-ok-2"})
	if rr.Code != http.StatusOK {
		t.Fatalf("uncontended PATCH: %d %s", rr.Code, rr.Body.String())
	}
}

// Reverse path (SaaS 4c N5): this value was sealed by the phase 4b code (submcp:prev,
// image 9515fa986fec) with TENANT_SECRET_KEY "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
// owner "owner-golden-000000000000000000001", server "22222222-3333-4444-8555-666666666666",
// header "Authorization". If the 4c code could not open it, a rollback to 4b would
// be unsafe for rows written by 4c, or the reverse. The 4c code writes the same format.
func TestN5GoldenV2ValueFrom4bOpens(t *testing.T) {
	box, err := NewSecretBox("MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := json.Marshal(map[string]string{"Authorization": "enc:v2:wbzm8X5lSzPCNbcsJ4A93t3GlWhi_H-R3tiLnrtq58Ws0itNe_th7sF-dfW_DI3GiLJ6a3Huiuw"})
	got, err := OpenSealedHeaders(stored, box, "owner-golden-000000000000000000001", "22222222-3333-4444-8555-666666666666")
	if err != nil || got["Authorization"] != "Bearer golden-4b-vector-7531" {
		t.Fatalf("a v2 value sealed by 4b must open under 4c: %v", err)
	}
}
