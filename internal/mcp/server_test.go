package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// fakeDB implements the minimal surface Server needs for session tests.
type fakeDB struct {
	endpoints map[string]*db.Endpoint
}

func (f *fakeDB) GetEndpointByName(_ context.Context, name string) (*db.Endpoint, error) {
	return f.endpoints[name], nil
}

func (f *fakeDB) ListEndpoints(_ context.Context) ([]db.Endpoint, error) {
	var out []db.Endpoint
	for _, e := range f.endpoints {
		out = append(out, *e)
	}
	return out, nil
}

func (f *fakeDB) Ping(_ context.Context) error { return nil }

func newTestServer() *Server {
	epA := &db.Endpoint{
		UUID: "ep-a", Name: "a", NamespaceUUID: "ns-a",
		EnableAPIKeyAuth: false,
	}
	epB := &db.Endpoint{
		UUID: "ep-b", Name: "b", NamespaceUUID: "ns-b",
		EnableAPIKeyAuth: false,
	}
	fdb := &fakeDB{endpoints: map[string]*db.Endpoint{"a": epA, "b": epB}}
	s := NewServer(fdb, nil, NewPool(10, 5, time.Minute), nil, time.Hour)
	return s
}

func doPost(t *testing.T, s *Server, path, sessionID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sessionID != "" {
		req.Header.Set("mcp-session-id", sessionID)
	}
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	return rr
}

// TestSessionBoundToEndpoint: a session created on endpoint A must NOT be
// usable against endpoint B (negative test for P0-1).
func TestSessionBoundToEndpoint(t *testing.T) {
	s := newTestServer()

	// Initialize on endpoint A.
	rr := doPost(t, s, "/metamcp/a/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("initialize on A: got %d", rr.Code)
	}
	sid := rr.Header().Get("mcp-session-id")
	if sid == "" {
		t.Fatalf("no session id returned")
	}

	// tools/list on endpoint B with A's session -> must 404.
	rr = doPost(t, s, "/metamcp/b/mcp", sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-endpoint session must 404, got %d", rr.Code)
	}
	// The 404 body must NOT leak OTHER session IDs (available_sessions
	// must be empty). The message field echoing the requested sid is the
	// wire shape — that's the client's own ID.
	body := rr.Body.String()
	if !strings.Contains(body, `"available_sessions":[]`) {
		t.Fatalf("expected empty available_sessions, got: %s", body)
	}

	// tools/list on endpoint A with A's session -> must work (200).
	// (Uses DELETE instead of tools/list to avoid needing a live
	// aggregator: a 200 DELETE proves the session is valid and bound.)
	req2 := httptest.NewRequest(http.MethodDelete, "/metamcp/a/mcp", nil)
	req2.Header.Set("mcp-session-id", sid)
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("same-endpoint session must work, got %d", rr2.Code)
	}
}

// TestInitializeMintsFreshSessionID: a client-supplied mcp-session-id on
// initialize must be ignored (fresh UUID minted) — no rebinding.
func TestInitializeMintsFreshSessionID(t *testing.T) {
	s := newTestServer()
	rr := doPost(t, s, "/metamcp/a/mcp", "00000000-0000-0000-0000-000000000000",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("initialize: got %d", rr.Code)
	}
	sid := rr.Header().Get("mcp-session-id")
	if sid == "00000000-0000-0000-0000-000000000000" {
		t.Fatalf("initialize must mint a fresh session id, not trust the client header")
	}
	if sid == "" {
		t.Fatalf("no session id returned")
	}
}

// TestDeleteCrossEndpoint: deleting a session from a different endpoint
// must 404 and NOT release the session.
func TestDeleteCrossEndpoint(t *testing.T) {
	s := newTestServer()
	rr := doPost(t, s, "/metamcp/a/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	sid := rr.Header().Get("mcp-session-id")

	// Delete from endpoint B -> 404.
	req := httptest.NewRequest(http.MethodDelete, "/metamcp/b/mcp", nil)
	req.Header.Set("mcp-session-id", sid)
	rr2 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr2, req)
	if rr2.Code != http.StatusNotFound {
		t.Fatalf("cross-endpoint delete must 404, got %d", rr2.Code)
	}

	// Session must still work on A: a same-endpoint DELETE must succeed
	// (200), proving the session survived the cross-endpoint delete.
	req2 := httptest.NewRequest(http.MethodDelete, "/metamcp/a/mcp", nil)
	req2.Header.Set("mcp-session-id", sid)
	rr3 := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr3, req2)
	if rr3.Code != http.StatusOK {
		t.Fatalf("session should survive cross-endpoint delete, got %d", rr3.Code)
	}
}

// TestNotificationGetsNoResponse: id-less requests (notifications) must
// return 202 with an empty body, not a JSON-RPC error.
func TestNotificationGetsNoResponse(t *testing.T) {
	s := newTestServer()
	rr := doPost(t, s, "/metamcp/a/mcp", "", `{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}`)
	if rr.Code != http.StatusAccepted {
		t.Fatalf("notification must return 202, got %d", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "" {
		t.Fatalf("notification must have empty body, got: %q", rr.Body.String())
	}
}

// TestMissingSessionIDOnNonInitialize: tools/list without a session id must
// 400 (P2-6), not invent a UUID and 404.
func TestMissingSessionIDOnNonInitialize(t *testing.T) {
	s := newTestServer()
	rr := doPost(t, s, "/metamcp/a/mcp", "", `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("missing session on tools/list must 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "missing_session") {
		t.Fatalf("expected missing_session error, got: %s", rr.Body.String())
	}
}

// TestInitializeEchoesSupportedVersion: a client requesting a supported
// protocol version gets it echoed (P1-10).
func TestInitializeEchoesSupportedVersion(t *testing.T) {
	s := newTestServer()
	rr := doPost(t, s, "/metamcp/a/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("initialize: got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"protocolVersion":"2025-06-18"`) {
		t.Fatalf("expected echoed version, got: %s", rr.Body.String())
	}
	// Capabilities must advertise tools only (P1-10).
	if strings.Contains(rr.Body.String(), `"prompts"`) || strings.Contains(rr.Body.String(), `"resources"`) {
		t.Fatalf("must not advertise unimplemented capabilities: %s", rr.Body.String())
	}
}

// TestInitializeFallsBackOnUnknownVersion: an unsupported client version
// falls back to 2025-03-26 (P1-10).
func TestInitializeFallsBackOnUnknownVersion(t *testing.T) {
	s := newTestServer()
	rr := doPost(t, s, "/metamcp/a/mcp", "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("initialize: got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"protocolVersion":"2025-03-26"`) {
		t.Fatalf("expected fallback version, got: %s", rr.Body.String())
	}
}

// TestSessionTTLExpires: a session older than the TTL must be rejected by
// Get and removed by Sweep (P1-4).
func TestSessionTTLExpires(t *testing.T) {
	store := NewSessionStore(50 * time.Millisecond)
	store.Put("s1", "ns-a", "ep-a")

	// Fresh: valid.
	if _, ok := store.Get("s1", "ep-a"); !ok {
		t.Fatalf("fresh session must be valid")
	}

	time.Sleep(80 * time.Millisecond)

	// Expired: Get must reject (lazy expiry).
	if _, ok := store.Get("s1", "ep-a"); ok {
		t.Fatalf("expired session must be rejected by Get")
	}

	// Sweep must return the remaining expired id (s1 was already removed
	// lazily by the Get above).
	store.Put("s2", "ns-a", "ep-a")
	time.Sleep(80 * time.Millisecond)
	expired := store.Sweep()
	if len(expired) != 1 || expired[0] != "s2" {
		t.Fatalf("sweep must return the remaining expired session, got %v", expired)
	}
}

// TestSessionTTLZeroNoExpiry: TTL 0 means no expiry (P1-4 explicit opt-out).
func TestSessionTTLZeroNoExpiry(t *testing.T) {
	store := NewSessionStore(0)
	store.Put("s1", "ns-a", "ep-a")
	time.Sleep(20 * time.Millisecond)
	if _, ok := store.Get("s1", "ep-a"); !ok {
		t.Fatalf("TTL 0 must never expire")
	}
	if expired := store.Sweep(); len(expired) != 0 {
		t.Fatalf("TTL 0 sweep must be a no-op, got %v", expired)
	}
}

// TestCORSPreflight: OPTIONS must return 204 with allow headers and echo
// the origin (P2-5a).
func TestCORSPreflight(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodOptions, "/metamcp/a/mcp", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("preflight must 204, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Fatalf("origin must be echoed, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Methods"); !strings.Contains(got, "POST") {
		t.Fatalf("methods must include POST, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "mcp-session-id") {
		t.Fatalf("headers must include mcp-session-id, got %q", got)
	}
}

// TestCORSActualRequest: a real request with Origin gets the echo header.
func TestCORSActualRequest(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPost, "/metamcp/a/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Fatalf("origin must be echoed on actual request, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("credentials must be allowed, got %q", got)
	}
}

// TestEndpointEnumerationStripsSensitive: the unauthenticated endpoint
// list must NOT expose user_id, namespace_uuid, or enable_api_key_auth
// (P1-17).
func TestEndpointEnumerationStripsSensitive(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/metamcp/", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("enumeration must 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, leaked := range []string{"user_id", "namespace_uuid", "enable_api_key_auth"} {
		if strings.Contains(body, leaked) {
			t.Fatalf("enumeration must not leak %q: %s", leaked, body)
		}
	}
	if !strings.Contains(body, `"name":"a"`) {
		t.Fatalf("enumeration must still list endpoint names: %s", body)
	}
}

// TestAuthScoping exercises the REAL Auth.Authenticate against a fake
// key store (P0-1.5): public keys must not reach private endpoints, and
// private keys only reach their own endpoints.
func TestAuthScoping(t *testing.T) {
	keys := map[string]*db.APIKey{
		"pub-key":  {UserID: nil},
		"x-key":    {UserID: strPtr("user-x")},
		"y-key":    {UserID: strPtr("user-y")},
	}
	fdb := &fakeKeyDB{keys: keys}
	a := NewAuth(fdb)

	cases := []struct {
		name     string
		key      string
		epUser   *string
		wantCode int
	}{
		{"public key on public endpoint", "pub-key", nil, http.StatusOK},
		{"public key on private endpoint (P0-1.5)", "pub-key", strPtr("user-x"), http.StatusForbidden},
		{"own key on own endpoint", "x-key", strPtr("user-x"), http.StatusOK},
		{"other key on endpoint", "y-key", strPtr("user-x"), http.StatusForbidden},
		{"private key on public endpoint", "x-key", nil, http.StatusOK},
		{"bad key", "nope", nil, http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ep := &db.Endpoint{UserID: tc.epUser, EnableAPIKeyAuth: true}
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/metamcp/x/mcp", nil)
			if tc.key != "" {
				req.Header.Set("X-API-Key", tc.key)
			}
			ok := a.Authenticate(rr, req, ep)
			if tc.wantCode == http.StatusOK && !ok {
				t.Fatalf("expected allow, got deny: %s", rr.Body.String())
			}
			if tc.wantCode != http.StatusOK && ok {
				t.Fatalf("expected deny, got allow")
			}
			if rr.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d (body %s)", rr.Code, tc.wantCode, rr.Body.String())
			}
		})
	}
}

// TestOAuthOnlyEndpointDenied (P0-1.4): an OAuth-only endpoint must issue
// the challenge and deny — submcp cannot validate OAuth tokens.
func TestOAuthOnlyEndpointDenied(t *testing.T) {
	a := NewAuth(&fakeKeyDB{keys: map[string]*db.APIKey{}})
	ep := &db.Endpoint{EnableAPIKeyAuth: false, EnableOAuth: true}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/metamcp/x/mcp", nil)
	if a.Authenticate(rr, req, ep) {
		t.Fatalf("OAuth-only endpoint must deny (no OAuth support)")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if ww := rr.Header().Get("WWW-Authenticate"); !strings.Contains(ww, `Bearer realm="MetaMCP"`) {
		t.Fatalf("missing WWW-Authenticate challenge: %q", ww)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["error"] != "authentication_required" {
		t.Fatalf("error = %v, want authentication_required", body["error"])
	}
	if body["resource_metadata"] == nil {
		t.Fatalf("missing resource_metadata in challenge body")
	}
}

// fakeKeyDB is a minimal KeyValidator for auth tests.
type fakeKeyDB struct {
	keys map[string]*db.APIKey
}

func (f *fakeKeyDB) ValidateAPIKey(_ context.Context, key string) (*db.APIKey, error) {
	k, ok := f.keys[key]
	if !ok {
		return nil, nil
	}
	return k, nil
}

func strPtr(s string) *string { return &s }

// silence unused import warnings in some build modes
var _ = json.RawMessage{}
