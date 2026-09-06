package httpapi_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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

// Golden parity tests: drive the FULL production handler chain
// (httpapi.Build — including the request-logging wrapper) over a real
// net/http server. The P0-1.1 SSE 500s existed because unit tests called
// srv.Handler() directly and never exercised the logging wrapper.

// --- fakes ---

type fakeEndpointStore struct {
	endpoints map[string]*db.Endpoint
}

func (f *fakeEndpointStore) GetEndpointByName(_ context.Context, name string) (*db.Endpoint, error) {
	return f.endpoints[name], nil
}
func (f *fakeEndpointStore) ListEndpoints(_ context.Context) ([]db.Endpoint, error) {
	var out []db.Endpoint
	for _, e := range f.endpoints {
		out = append(out, *e)
	}
	return out, nil
}
func (f *fakeEndpointStore) Ping(_ context.Context) error { return nil }

type fakeToolStore struct{}

func (f *fakeToolStore) GetActiveServersForNamespace(_ context.Context, _ string) ([]db.MCPServer, error) {
	return nil, nil
}
func (f *fakeToolStore) GetToolMappings(_ context.Context, _ string) ([]struct {
	Mapping db.NamespaceToolMapping
	Tool    db.Tool
}, error) {
	return nil, nil
}
func (f *fakeToolStore) SyncTools(_ context.Context, _ string, _ []db.SyncToolInput) error {
	return nil
}
func (f *fakeToolStore) SetServerErrorStatus(_ context.Context, _ string, _ db.ErrorStatus) error {
	return nil
}

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

// fakeUIStore satisfies ui.Store with no-ops (golden tests exercise the
// gateway, not the admin console).
type fakeUIStore struct{}

func (f *fakeUIStore) CountNamespaces(context.Context) (int, error) { return 0, nil }
func (f *fakeUIStore) CountTools(context.Context) (int, error)      { return 0, nil }
func (f *fakeUIStore) CreateAPIKey(context.Context, string, string, bool) (*db.APIKey, error) {
	return nil, nil
}
func (f *fakeUIStore) CreateEndpoint(context.Context, *db.Endpoint) error { return nil }
func (f *fakeUIStore) CreateNamespace(context.Context, *db.Namespace) error {
	return nil
}
func (f *fakeUIStore) CreateServer(context.Context, *db.MCPServer) error { return nil }
func (f *fakeUIStore) DeleteEndpoint(context.Context, string) error     { return nil }
func (f *fakeUIStore) DeleteNamespace(context.Context, string) error    { return nil }
func (f *fakeUIStore) DeleteServer(context.Context, string) error        { return nil }
func (f *fakeUIStore) GetServer(context.Context, string) (*db.MCPServer, error) {
	return nil, nil
}
func (f *fakeUIStore) ListAPIKeys(context.Context) ([]db.APIKey, error) { return nil, nil }
func (f *fakeUIStore) ListEndpoints(context.Context) ([]db.Endpoint, error) {
	return nil, nil
}
func (f *fakeUIStore) ListNamespaceServerMappings(context.Context, string) ([]db.NamespaceServerMapping, error) {
	return nil, nil
}
func (f *fakeUIStore) ListNamespaces(context.Context) ([]db.Namespace, error) { return nil, nil }
func (f *fakeUIStore) ListServers(context.Context) ([]db.MCPServer, error)    { return nil, nil }
func (f *fakeUIStore) SetAPIKeyActive(context.Context, string, bool) error    { return nil }
func (f *fakeUIStore) SetServerMapping(context.Context, string, string, db.ServerStatus) error {
	return nil
}
func (f *fakeUIStore) UpdateEndpoint(context.Context, *db.Endpoint) error { return nil }
func (f *fakeUIStore) UpdateServer(context.Context, *db.MCPServer) error  { return nil }
func (f *fakeUIStore) ValidateAPIKey(context.Context, string) (*db.APIKey, error) {
	return nil, nil
}

// --- harness ---

// newGoldenServer builds the production chain and returns a live
// httptest.Server (real net/http ResponseWriter — Flusher is real).
func newGoldenServer(t *testing.T, endpoints map[string]*db.Endpoint, keys map[string]*db.APIKey) *httptest.Server {
	t.Helper()
	epStore := &fakeEndpointStore{endpoints: endpoints}
	pool := mcp.NewPool(10, 5, time.Minute)
	agg := mcp.NewAggregator(pool, &fakeToolStore{})
	auth := mcp.NewAuth(&fakeKeyDB{keys: keys})
	srv := mcp.NewServer(epStore, agg, pool, auth, time.Hour)
	adminUI := ui.New(&fakeUIStore{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := httpapi.Build(logger, srv, adminUI)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

func openEndpoint() *db.Endpoint {
	return &db.Endpoint{
		UUID: "ep-1", Name: "all", NamespaceUUID: "ns-1",
		EnableAPIKeyAuth: false,
	}
}

func openEndpoints() map[string]*db.Endpoint {
	return map[string]*db.Endpoint{"all": openEndpoint()}
}

// --- tests ---

// TestGoldenSSEStreamsSurviveLoggingWrapper is the P0-1.1 regression
// test: both SSE endpoints must stream through the FULL chain (logging
// wrapper included), not 500.
func TestGoldenSSEStreamsSurviveLoggingWrapper(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)

	// Legacy SSE: GET /sse must open a stream and emit the endpoint event.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/metamcp/all/sse", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /sse: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /sse status = %d, want 200 (P0-1.1 regression)", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("GET /sse content-type = %q, want text/event-stream", ct)
	}
	// First frame must be the endpoint event.
	br := bufio.NewReader(resp.Body)
	line1, _ := br.ReadString('\n')
	line2, _ := br.ReadString('\n')
	if !strings.Contains(line1, "event: endpoint") {
		t.Fatalf("first SSE line = %q, want event: endpoint", line1)
	}
	if !strings.Contains(line2, "data: /metamcp/all/message?sessionId=") {
		t.Fatalf("second SSE line = %q, want data: /metamcp/all/message?sessionId=...", line2)
	}
}

// TestGoldenStreamableGETSurvivesLoggingWrapper: streamable GET must open
// and emit a heartbeat (P0-1.1 regression).
func TestGoldenStreamableGETSurvivesLoggingWrapper(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)

	// Initialize to get a session.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"golden","version":"1.0"}}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/mcp", strings.NewReader(initBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sid := resp.Header.Get("mcp-session-id")
	if sid == "" {
		t.Fatalf("no mcp-session-id from initialize")
	}

	// Streamable GET with that session.
	req2, _ := http.NewRequest(http.MethodGet, ts.URL+"/metamcp/all/mcp", nil)
	req2.Header.Set("mcp-session-id", sid)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("GET /mcp: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET /mcp status = %d, want 200 (P0-1.1 regression)", resp2.StatusCode)
	}
	// Heartbeat arrives within ~16s (15s ticker). Read with a timeout.
	type lineResult struct {
		line string
		err  error
	}
	ch := make(chan lineResult, 1)
	go func() {
		line, err := bufio.NewReader(resp2.Body).ReadString('\n')
		ch <- lineResult{line, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("expected heartbeat frame, got err: %v", r.err)
		}
		if !strings.Contains(r.line, "heartbeat") {
			t.Fatalf("expected heartbeat, got %q", r.line)
		}
	case <-time.After(17 * time.Second):
		t.Fatalf("timed out waiting for heartbeat frame")
	}
}

// TestGoldenLegacySSERoundTrip: POST /message returns 202 and the
// JSON-RPC response arrives as event:message on the open stream
// (P0-1.11 parity with the SDK's handlePostMessage).
func TestGoldenLegacySSERoundTrip(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)

	// Open the SSE stream in a goroutine, capture frames.
	frames := make(chan string, 8)
	done := make(chan struct{})
	var streamBody io.ReadCloser
	go func() {
		defer close(done)
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/metamcp/all/sse", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			frames <- "ERR: " + err.Error()
			return
		}
		streamBody = resp.Body
		br := bufio.NewReader(resp.Body)
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			frames <- strings.TrimRight(line, "\n")
		}
	}()
	t.Cleanup(func() {
		if streamBody != nil {
			streamBody.Close()
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	})

	// Wait for the endpoint event to learn the session id.
	var sid string
	deadline := time.After(5 * time.Second)
	for sid == "" {
		select {
		case f := <-frames:
			if strings.HasPrefix(f, "data: /metamcp/all/message?sessionId=") {
				sid = strings.TrimPrefix(f, "data: /metamcp/all/message?sessionId=")
			}
		case <-deadline:
			t.Fatalf("timed out waiting for endpoint event")
		}
	}

	// POST a tools/list message.
	msgBody := `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/message?sessionId="+sid, strings.NewReader(msgBody))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /message: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST /message status = %d, want 202", resp.StatusCode)
	}

	// The response must arrive as event:message on the stream.
	deadline2 := time.After(5 * time.Second)
	var gotData string
	for gotData == "" {
		select {
		case f := <-frames:
			if strings.HasPrefix(f, "data: ") {
				gotData = strings.TrimPrefix(f, "data: ")
			}
		case <-deadline2:
			t.Fatalf("timed out waiting for response frame on stream")
		}
	}
	var rpc struct {
		ID     json.RawMessage `json:"id"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(gotData), &rpc); err != nil {
		t.Fatalf("response frame not JSON-RPC: %v (%s)", err, gotData)
	}
	if string(rpc.ID) != "7" {
		t.Fatalf("response id = %s, want 7", rpc.ID)
	}
	if len(rpc.Result) == 0 {
		t.Fatalf("response has no result: %s", gotData)
	}
}

// TestGoldenAuthShapes: byte-compare auth error bodies against the
// captured fixtures (modulo timestamp).
func TestGoldenAuthShapes(t *testing.T) {
	keys := map[string]*db.APIKey{"good-key": {UserID: nil}}
	ep := &db.Endpoint{
		UUID: "ep-1", Name: "all", NamespaceUUID: "ns-1",
		EnableAPIKeyAuth: true,
	}
	ts := newGoldenServer(t, map[string]*db.Endpoint{"all": ep}, keys)

	// No key -> authentication_required (fixture auth-none.json shape).
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("no-key request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-key status = %d, want 401", resp.StatusCode)
	}
	var j map[string]any
	_ = json.Unmarshal(body, &j)
	if j["error"] != "authentication_required" {
		t.Fatalf("no-key error = %v, want authentication_required", j["error"])
	}
	if j["supported_methods"] == nil {
		t.Fatalf("no-key body missing supported_methods: %s", body)
	}

	// Bad key -> invalid_api_key (fixture auth-badkey.json shape).
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("X-API-Key", "wrong-key")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("bad-key request: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad-key status = %d, want 401", resp2.StatusCode)
	}
	_ = json.Unmarshal(body2, &j)
	if j["error"] != "invalid_api_key" {
		t.Fatalf("bad-key error = %v, want invalid_api_key", j["error"])
	}

	// Unknown endpoint -> 404 (fixture auth-unknown-ep.json shape).
	req3, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/nonexistent/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	req3.Header.Set("Content-Type", "application/json")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("unknown-ep request: %v", err)
	}
	body3, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown-ep status = %d, want 404", resp3.StatusCode)
	}
	_ = json.Unmarshal(body3, &j)
	if j["error"] != "Endpoint not found" {
		t.Fatalf("unknown-ep error = %v, want 'Endpoint not found'", j["error"])
	}
}

// TestGoldenSessionNotFoundNoLeak: unknown session -> 404 with
// available_sessions:[] (never leaks live session IDs).
func TestGoldenSessionNotFoundNoLeak(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("mcp-session-id", "00000000-0000-0000-0000-000000000000")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if !strings.Contains(string(body), `"available_sessions":[]`) {
		t.Fatalf("body must have empty available_sessions (no leak): %s", body)
	}
}

// TestGoldenSecurityHeaders: every response carries the P2-5b headers.
func TestGoldenSecurityHeaders(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()
	for _, h := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing security header %s", h)
		}
	}
}

// TestGoldenRateLimit429: the per-IP limiter returns 429 with the exact
// body shape through the full chain.
func TestGoldenRateLimit429(t *testing.T) {
	// Burst 1, rate 1/s — the second request in the same second is limited.
	epStore := &fakeEndpointStore{endpoints: openEndpoints()}
	pool := mcp.NewPool(10, 5, time.Minute)
	agg := mcp.NewAggregator(pool, &fakeToolStore{})
	auth := mcp.NewAuth(&fakeKeyDB{keys: nil})
	srv := mcp.NewServer(epStore, agg, pool, auth, time.Hour)
	// Override the limiter with a tight one.
	srv.SetRateLimiter(mcp.NewRateLimiter(1, 1))
	adminUI := ui.New(&fakeUIStore{})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	handler := httpapi.Build(logger, srv, adminUI)
	ts := httptest.NewServer(handler)
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/health", nil)
	resp1, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first request status = %d, want 200", resp1.StatusCode)
	}

	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second request status = %d, want 429", resp2.StatusCode)
	}
	if !strings.Contains(string(body), `"error":"rate_limited"`) {
		t.Fatalf("429 body shape wrong: %s", body)
	}
}

// TestGoldenInitializeFraming: initialize through the full chain returns
// 200, mcp-session-id, and SSE framing (event: message / data:).
func TestGoldenInitializeFraming(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"golden","version":"1.0"}}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/mcp", strings.NewReader(initBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("initialize: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if resp.Header.Get("mcp-session-id") == "" {
		t.Fatalf("missing mcp-session-id header")
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}
	s := string(body)
	if !strings.Contains(s, "event: message") || !strings.Contains(s, "data: ") {
		t.Fatalf("initialize not SSE-framed: %s", s)
	}
	if !strings.Contains(s, `"protocolVersion":"2025-03-26"`) {
		t.Fatalf("protocolVersion not echoed: %s", s)
	}
}

// TestGoldenCORS: preflight through the full chain returns 204 with the
// allow headers (P2-5a).
func TestGoldenCORS(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)
	req, _ := http.NewRequest(http.MethodOptions, ts.URL+"/metamcp/all/mcp", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("preflight: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Fatalf("allow-origin = %q, want echo", resp.Header.Get("Access-Control-Allow-Origin"))
	}
	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "POST") {
		t.Fatalf("allow-methods missing POST: %q", resp.Header.Get("Access-Control-Allow-Methods"))
	}
}

// TestGoldenNotification202: a JSON-RPC notification (no id) gets 202
// with an empty body (P1-8).
func TestGoldenNotification202(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)
	body := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("notification: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("notification status = %d, want 202", resp.StatusCode)
	}
	if len(got) != 0 {
		t.Fatalf("notification body must be empty, got %q", got)
	}
}

// TestGoldenMissingSession400: non-initialize without mcp-session-id ->
// 400 missing_session (P2-6).
func TestGoldenMissingSession400(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if !strings.Contains(string(body), "missing_session") {
		t.Fatalf("body missing missing_session: %s", body)
	}
}

// TestGoldenUnknownMethod: unknown JSON-RPC method -> -32601 inside a
// 200 SSE frame.
func TestGoldenUnknownMethod(t *testing.T) {
	ts := newGoldenServer(t, openEndpoints(), nil)
	// Initialize first.
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"golden","version":"1.0"}}}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/mcp", strings.NewReader(initBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, _ := http.DefaultClient.Do(req)
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	sid := resp.Header.Get("mcp-session-id")

	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/metamcp/all/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"bogus/method","params":{}}`))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Accept", "application/json, text/event-stream")
	req2.Header.Set("mcp-session-id", sid)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("unknown method: %v", err)
	}
	body, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("unknown method status = %d, want 200 (RPC error in frame)", resp2.StatusCode)
	}
	if !strings.Contains(string(body), "-32601") {
		t.Fatalf("unknown method must carry -32601: %s", body)
	}
}

var _ = fmt.Sprintf // keep fmt import if unused in future edits
