package mcp

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

func TestToolsListResultIsEmptyArrayNotNull(t *testing.T) {
	b, err := json.Marshal(toolsListResult(nil))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"tools":[]}` {
		t.Fatalf("nil tools marshal to %s, want {\"tools\":[]}", b)
	}
}

// A namespace with no upstreams (a brand-new tenant) must answer tools/list
// with "tools":[] on the wire, never "tools":null.
func TestToolsListWithNoUpstreamsIsEmptyArray(t *testing.T) {
	ep := &db.Endpoint{UUID: "ep-empty", Name: "all", NamespaceUUID: "ns-empty"}
	endpoints := &fakeDB{endpoints: map[string]*db.Endpoint{"all": ep}}
	agg := NewAggregator(NewPool(10, 5, time.Minute), &fakeDB2{})
	s := NewServer(endpoints, agg, NewPool(10, 5, time.Minute), nil, time.Hour)

	rr := doPost(t, s, "/metamcp/all/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("initialize: status %d", rr.Code)
	}
	sid := rr.Header().Get("mcp-session-id")
	if sid == "" {
		t.Fatal("initialize returned no mcp-session-id")
	}

	rr = doPost(t, s, "/metamcp/all/mcp", sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("tools/list: status %d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, `"tools":[]`) || strings.Contains(body, `"tools":null`) {
		t.Fatalf("tools/list body = %s, want \"tools\":[]", body)
	}
}
