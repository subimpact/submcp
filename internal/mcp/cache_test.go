package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// fakeUpstream is a minimal MCP streamable-HTTP upstream that serves a
// fixed tools/list and counts calls.
type fakeUpstream struct {
	srv      *httptest.Server
	calls    atomic.Int64
	tools    []Tool
	down     atomic.Bool
	initSeen atomic.Bool
}

func newFakeUpstream(tools []Tool) *fakeUpstream {
	f := &fakeUpstream{tools: tools}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.calls.Add(1)
		if f.down.Load() {
			http.Error(w, "upstream down", http.StatusServiceUnavailable)
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			f.initSeen.Store(true)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]any{
					"protocolVersion": "2025-03-26",
					"capabilities":    map[string]any{},
					"serverInfo":      map[string]any{"name": "fake", "version": "1.0"},
				},
			})
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]any{"tools": f.tools},
			})
		case "tools/call":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": "ok"}},
				},
			})
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	}))
	return f
}

func (f *fakeUpstream) close() { f.srv.Close() }

func fakeServerForTest(s db.MCPServer) db.MCPServer {
	url := s.URL
	if url == nil {
		u := ""
		url = &u
	}
	return db.MCPServer{
		UUID: s.UUID, Name: s.Name, Type: db.ServerTypeStreamableHTTP,
		URL: url,
	}
}

// fakeDB2 is a minimal EndpointStore + tool-mapping source for aggregator tests.
type fakeDB2 struct {
	servers  []db.MCPServer
	mappings []struct {
		Mapping db.NamespaceToolMapping
		Tool    db.Tool
	}
}

func (f *fakeDB2) GetActiveServersForNamespace(ctx context.Context, namespaceUUID string) ([]db.MCPServer, error) {
	return f.servers, nil
}
func (f *fakeDB2) GetToolMappings(ctx context.Context, namespaceUUID string) ([]struct {
	Mapping db.NamespaceToolMapping
	Tool    db.Tool
}, error) {
	return f.mappings, nil
}
func (f *fakeDB2) SyncTools(ctx context.Context, serverUUID string, tools []db.SyncToolInput) error {
	return nil
}

func TestToolCacheHitsSecondList(t *testing.T) {
	up := newFakeUpstream([]Tool{{Name: "alpha", InputSchema: json.RawMessage(`{"type":"object"}`)}})
	defer up.close()

	agg := NewAggregator(NewPool(10, 5, time.Minute), &fakeDB2{
		servers: []db.MCPServer{fakeServerForTest(db.MCPServer{
			UUID: "srv-1", Name: "fake", URL: &up.srv.URL,
		})},
	})

	ctx := context.Background()
	first, err := agg.ListTools(ctx, "ns-1")
	if err != nil {
		t.Fatalf("first list: %v", err)
	}
	if len(first) != 1 || first[0].Name != "fake__alpha" {
		t.Fatalf("first list wrong: %+v", first)
	}
	callsAfterFirst := up.calls.Load()

	second, err := agg.ListTools(ctx, "ns-1")
	if err != nil {
		t.Fatalf("second list: %v", err)
	}
	if len(second) != 1 {
		t.Fatalf("second list wrong: %+v", second)
	}
	if up.calls.Load() != callsAfterFirst {
		t.Fatalf("cache miss: upstream calls %d -> %d (expected no new calls)", callsAfterFirst, up.calls.Load())
	}
}

func TestServeStaleOnUpstreamFailure(t *testing.T) {
	up := newFakeUpstream([]Tool{{Name: "alpha", InputSchema: json.RawMessage(`{"type":"object"}`)}})
	defer up.close()

	agg := NewAggregator(NewPool(10, 5, time.Minute), &fakeDB2{
		servers: []db.MCPServer{fakeServerForTest(db.MCPServer{
			UUID: "srv-1", Name: "fake", URL: &up.srv.URL,
		})},
	})

	ctx := context.Background()
	if _, err := agg.ListTools(ctx, "ns-1"); err != nil {
		t.Fatalf("warm list: %v", err)
	}

	// Kill the upstream, force cache expiry, list again -> serve stale.
	up.down.Store(true)
	agg.toolMu.Lock()
	agg.toolCache["srv-1"].at = time.Now().Add(-2 * toolCacheTTL)
	agg.toolMu.Unlock()

	stale, err := agg.ListTools(ctx, "ns-1")
	if err != nil {
		t.Fatalf("serve-stale list failed: %v", err)
	}
	if len(stale) != 1 || stale[0].Name != "fake__alpha" {
		t.Fatalf("stale list wrong: %+v", stale)
	}
}

func TestCallToolRoutesViaMap(t *testing.T) {
	up := newFakeUpstream([]Tool{{Name: "alpha", InputSchema: json.RawMessage(`{"type":"object"}`)}})
	defer up.close()

	agg := NewAggregator(NewPool(10, 5, time.Minute), &fakeDB2{
		servers: []db.MCPServer{fakeServerForTest(db.MCPServer{
			UUID: "srv-1", Name: "fake", URL: &up.srv.URL,
		})},
	})

	ctx := context.Background()
	// CallTool BEFORE any ListTools: build-on-demand route map.
	_, err := agg.CallTool(ctx, "ns-1", "sess-1", "fake__alpha", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("call via route map: %v", err)
	}
	if !up.initSeen.Load() {
		t.Fatalf("upstream was never contacted")
	}
}
