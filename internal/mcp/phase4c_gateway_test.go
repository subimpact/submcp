package mcp

// SaaS phase 4c regressions for the gateway request path: client address on
// tenant hosts (N1), client cancellation (N7) and partial route maps (N9).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// N1: tenant subdomains are DNS-only, so Cloudflare never sets CF-Connecting-IP
// for them. A value there is the client's own header and must be ignored. The
// address comes from the TCP peer (or the trusted Traefik X-Forwarded-For).
func TestN1ClientIPIgnoresCFConnectingIPOnTenantHosts(t *testing.T) {
	if err := SetTrustedProxies("10.0.5.0/24"); err != nil {
		t.Fatal(err)
	}
	SetTenantBaseHost("mcp.subimpact.net")
	defer SetTrustedProxies("")
	defer SetTenantBaseHost("")

	cases := []struct {
		name, host, remote string
		headers            map[string]string
		want               string
	}{
		{"tenant host ignores a spoofed CF header, uses Traefik's XFF",
			"acme.mcp.subimpact.net", "10.0.5.4:4000",
			map[string]string{"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "198.51.100.9"}, "198.51.100.9"},
		{"tenant host with a port",
			"acme.mcp.subimpact.net:443", "10.0.5.4:4000",
			map[string]string{"CF-Connecting-IP": "1.2.3.4", "X-Forwarded-For": "198.51.100.9"}, "198.51.100.9"},
		{"tenant host, no XFF: the TCP peer, not the CF header",
			"acme.mcp.subimpact.net", "10.0.5.4:4000",
			map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "10.0.5.4"},
		{"tenant host, untrusted peer: the peer",
			"acme.mcp.subimpact.net", "203.0.113.9:4000",
			map[string]string{"CF-Connecting-IP": "1.2.3.4"}, "203.0.113.9"},
		{"apex host still trusts CF-Connecting-IP",
			"mcp.subimpact.net", "10.0.5.4:4000",
			map[string]string{"CF-Connecting-IP": "198.51.100.8"}, "198.51.100.8"},
		{"a name that only ends in the base host's letters is not a tenant",
			"attackermcp.subimpact.net", "10.0.5.4:4000",
			map[string]string{"CF-Connecting-IP": "198.51.100.8"}, "198.51.100.8"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "https://"+c.host+"/", nil)
		r.Host = c.host
		r.RemoteAddr = c.remote
		for k, v := range c.headers {
			r.Header.Set(k, v)
		}
		if got := ClientIP(r); got != c.want {
			t.Errorf("%s: ClientIP = %q, want %q", c.name, got, c.want)
		}
	}
}

// N7: a client that cancels a tool call is not an upstream failure. The call
// must not write ERROR or last_error on the tenant's server, however many times
// it happens (the breaker opens at 5, which would quarantine the server).
func TestN7CancelledCallLeavesStatusAndLastErrorAlone(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "fixture", "url": "https://" + fxUpstreamHost + "/mcp", "headers": map[string]string{},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)
	sess := fx.initSession("acme", keyA)
	// Warm the route map and the tool cache while the upstream answers.
	list := rpcResult(t, fx.mcp("acme", keyA, sess, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`).Body.String())
	if got := toolNames(t, list); len(got) == 0 {
		t.Fatalf("warm-up list is empty")
	}

	fx.up.setBehaviour(func(u *fxUpstream) { u.hang = true })
	for i := 0; i < 6; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(60*time.Millisecond, cancel)
		body := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fixture__echo","arguments":{"text":"hi"}}}`
		req := httptest.NewRequest(http.MethodPost, "https://acme."+fxBaseHost+"/metamcp/all/mcp", strings.NewReader(body)).WithContext(ctx)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("X-API-Key", keyA)
		req.Header.Set("mcp-session-id", sess)
		fx.srv.Handler().ServeHTTP(httptest.NewRecorder(), req)
		cancel()
	}
	fx.up.setBehaviour(func(u *fxUpstream) { u.hang = false })

	fx.db.mu.Lock()
	got := *fx.db.servers[id]
	fx.db.mu.Unlock()
	if got.ErrorStatus != db.ErrorStatusNone {
		t.Fatalf("client cancellations quarantined the server: error_status=%s", got.ErrorStatus)
	}
	if got.LastError != nil {
		t.Fatalf("client cancellation was recorded as an upstream failure: last_error=%q", *got.LastError)
	}
}

// N9: a route map built while one server errored is partial. It must not be
// cached, or that server's tools stay hidden for the whole TTL after it recovers.
func TestN9PartialRouteMapIsNotCached(t *testing.T) {
	good := newFakeUpstream([]Tool{{Name: "alpha", InputSchema: json.RawMessage(`{"type":"object"}`)}})
	defer good.close()
	bad := newFakeUpstream([]Tool{{Name: "beta", InputSchema: json.RawMessage(`{"type":"object"}`)}})
	defer bad.close()
	bad.down.Store(true)

	agg := NewAggregator(NewPool(10, 5, time.Minute), &fakeDB2{servers: []db.MCPServer{
		fakeServerForTest(db.MCPServer{UUID: "srv-good", Name: "good", URL: &good.srv.URL}),
		fakeServerForTest(db.MCPServer{UUID: "srv-bad", Name: "bad", URL: &bad.srv.URL}),
	}})
	ctx := context.Background()
	servers, err := agg.getServers(ctx, "ns-1")
	if err != nil {
		t.Fatal(err)
	}
	first, err := agg.buildRouteMap(ctx, "ns-1", servers)
	if err != nil {
		t.Fatalf("a partial map is still a result: %v", err)
	}
	if _, ok := first["good__alpha"]; !ok {
		t.Fatalf("healthy server missing from the map: %v", first)
	}
	if _, ok := first["bad__beta"]; ok {
		t.Fatal("the failing server cannot be in the map")
	}

	bad.down.Store(false) // the server recovers well inside the cache TTL
	second, err := agg.buildRouteMap(ctx, "ns-1", servers)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := second["bad__beta"]; !ok {
		t.Fatalf("a partial route map was cached: recovered tools are hidden (%v)", second)
	}
}

// N13 (SaaS 4c): the tenant tools/list byte cap counts across pages. Each page
// is 0.6 MiB, below the per-response cap, so only the running total can trip the
// 2 MiB aggregate cap: the fourth page does (2.4 MiB). Three pages (1.8 MiB) must
// still list, which shows the failure is the total, not the page.
func TestN13ToolsListCapAccumulatesAcrossPages(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	blob := strings.Repeat("d", 600<<10) // 0.6 MiB per page
	pages := func(n int) func(string) string {
		return func(cursor string) string {
			p := 0
			if cursor != "" {
				p, _ = strconv.Atoi(cursor)
			}
			next := ""
			if p+1 < n {
				next = strconv.Itoa(p + 1)
			}
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"big%d","description":"%s","inputSchema":{"type":"object"}}],"nextCursor":"%s"}}`, p, blob, next)
		}
	}
	list := func(n int) ([]Tool, error) {
		fx.up.setBehaviour(func(u *fxUpstream) { u.bigTools = pages(n) })
		c := NewUpstreamClient(UpstreamConfig{Name: "paged", URL: "https://" + fxUpstreamHost + "/mcp",
			Timeout: 20 * time.Second, Policy: fx.srv.agg.tenantPolicy})
		ctx := context.Background()
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		return c.ListTools(ctx)
	}

	tools, err := list(3)
	if err != nil || len(tools) != 3 {
		t.Fatalf("three 0.6 MiB pages (1.8 MiB) are within the cap: %d tools, %v", len(tools), err)
	}
	tools, err = list(5)
	if err == nil {
		t.Fatalf("five 0.6 MiB pages (3 MiB) passed the 2 MiB aggregate cap with %d tools", len(tools))
	}
	if len(tools) != 0 {
		t.Fatalf("a capped list must not return a partial result: %d tools", len(tools))
	}
}
