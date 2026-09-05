package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// paginatedUpstream serves tools/list in pages via nextCursor.
type paginatedUpstream struct {
	srv   *httptest.Server
	pages [][]Tool
	calls atomic.Int64
	lists atomic.Int64
}

func newPaginatedUpstream(pages [][]Tool) *paginatedUpstream {
	p := &paginatedUpstream{pages: pages}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.calls.Add(1)
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		method, _ := req["method"].(string)
		switch method {
		case "initialize":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]any{
					"protocolVersion": "2025-03-26",
					"capabilities":    map[string]any{},
					"serverInfo":      map[string]any{"name": "pag", "version": "1.0"},
				},
			})
		case "tools/list":
			p.lists.Add(1)
			params, _ := req["params"].(map[string]any)
			cursor, _ := params["cursor"].(string)
			idx := 0
			if cursor != "" {
				idx = int(cursor[0] - '0')
			}
			w.Header().Set("Content-Type", "application/json")
			result := map[string]any{"tools": p.pages[idx]}
			if idx+1 < len(p.pages) {
				next := string(rune('0' + idx + 1))
				result["nextCursor"] = next
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": req["id"], "result": result,
			})
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	}))
	return p
}

func (p *paginatedUpstream) close() { p.srv.Close() }

// TestListToolsFollowsPagination: tools/list must follow nextCursor until
// exhausted and return ALL tools (P1-12).
func TestListToolsFollowsPagination(t *testing.T) {
	up := newPaginatedUpstream([][]Tool{
		{{Name: "a", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		{{Name: "b", InputSchema: json.RawMessage(`{"type":"object"}`)}},
		{{Name: "c", InputSchema: json.RawMessage(`{"type":"object"}`)}},
	})
	defer up.close()

	client := NewUpstreamClient(UpstreamConfig{Name: "pag", URL: up.srv.URL, Timeout: 5 * time.Second})
	ctx := context.Background()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close(ctx)

	tools, err := client.ListTools(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tools) != 3 {
		t.Fatalf("expected 3 tools across pages, got %d", len(tools))
	}
	if up.lists.Load() != 3 {
		t.Fatalf("expected 3 tools/list calls (one per page), got %d", up.lists.Load())
	}
}
