package mcp

// Regression tests for the phase 4 security review (SaaS phase 4b). Each test
// is the assertion form of one proof-of-concept from the review (PoC1..PoC8).
// They must fail on the phase 4 code and pass after the fixes. Do not weaken
// them to make a build pass.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

const pocToken = "tenant-live-token-7777" // the credential the PoCs try to steal

// PoC1: a URL change that moves the stored credentials to another origin.
func TestPoC1_URLChangeWithoutFreshHeadersIsRefused(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "victim", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": "Bearer " + pocToken},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)

	// Only the URL changes to another host. Headers are omitted, so the sealed
	// value would be replayed to the new origin. It must be refused.
	rr = fx.api(keyA, "PATCH", "/api/tenant/servers/"+id, map[string]any{
		"url": "https://attacker.tenant-fixture.net/mcp",
	})
	if rr.Code != http.StatusBadRequest || errCode(t, rr) != "headers_required_for_new_origin" {
		t.Fatalf("origin change without headers: want 400 headers_required_for_new_origin, got %d %s", rr.Code, rr.Body.String())
	}
	// The stored URL did not move, and the attacker host was never contacted.
	if got := fx.db.servers[id].URL; got == nil || *got != "https://"+fxUpstreamHost+"/mcp" {
		t.Fatalf("stored URL changed despite the refusal: %v", got)
	}
	fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil)
	if h := fx.up.lastHost(); h == "attacker.tenant-fixture.net" {
		t.Fatal("the credential was sent to the attacker host")
	}
}

// A masked placeholder is not a fresh value: it must not carry the old secret
// to a new origin either.
func TestPoC1_MaskedHeaderCannotCarryAnOriginChange(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "victim", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": "Bearer " + pocToken},
	})
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)
	rr = fx.api(keyA, "PATCH", "/api/tenant/servers/"+id, map[string]any{
		"url":     "https://attacker.tenant-fixture.net/mcp",
		"headers": map[string]string{"Authorization": MaskSecret("Bearer " + pocToken)},
	})
	if rr.Code != http.StatusBadRequest || errCode(t, rr) != "headers_required_for_new_origin" {
		t.Fatalf("masked value on origin change: want 400, got %d %s", rr.Code, rr.Body.String())
	}
}

// PoC1 control: a path-only change keeps the stored headers and they still work.
func TestPoC1_PathOnlyChangeKeepsStoredHeaders(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "victim", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": "Bearer " + pocToken},
	})
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)
	rr = fx.api(keyA, "PATCH", "/api/tenant/servers/"+id, map[string]any{
		"url": "https://" + fxUpstreamHost + "/mcp/v2",
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("path-only change: %d %s", rr.Code, rr.Body.String())
	}
	rr = fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil)
	if !strings.Contains(rr.Body.String(), `"ok":true`) {
		t.Fatalf("test after path change: %s", rr.Body.String())
	}
	if got := fx.up.lastAuth(); got != "Bearer "+pocToken {
		t.Fatalf("stored credential not sent on the same origin: %q", got)
	}
}

// PoC2: IPv4 addresses hidden in IPv6 encodings must be blocked, and public
// addresses must stay allowed (the blocklist must not over-match).
func TestPoC2_InternalIPv4InIPv6EncodingsIsBlocked(t *testing.T) {
	blocked := []string{
		"::7f00:1",          // IPv4-compatible ::/96 of 127.0.0.1
		"::a00:1",           // IPv4-compatible ::/96 of 10.0.0.1
		"::ffff:0:7f00:1",   // SIIT ::ffff:0:0:0/96 of 127.0.0.1 (RFC 2765)
		"64:ff9b:1::7f00:1", // local-use NAT64 64:ff9b:1::/48 (RFC 8215)
		"::ffff:7f00:1",     // IPv4-mapped 127.0.0.1
		"::1",               // loopback
		"169.254.169.254",   // metadata
		"192.88.99.1",       // deprecated 6to4 relay anycast
	}
	for _, s := range blocked {
		if TenantIPAllowed(net.ParseIP(s)) {
			t.Errorf("%s must be blocked for tenant servers", s)
		}
	}
	allowed := []string{"93.184.216.34", "2606:4700::1111", "192.88.98.1"}
	for _, s := range allowed {
		if !TenantIPAllowed(net.ParseIP(s)) {
			t.Errorf("%s is public and must stay allowed", s)
		}
	}
}

// PoC2 (create path): an AAAA answer of the IPv4-compatible 127.0.0.1 is refused
// at create, before any connection (PoC4).
func TestPoC4_IPv4CompatibleAAAAAnswerIsRefusedAtCreate(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "v6probe", "url": "https://v6.tenant-fixture.net/mcp",
		"headers": map[string]string{},
	})
	if rr.Code != http.StatusBadRequest || errCode(t, rr) != "url_not_allowed" {
		t.Fatalf("AAAA ::7f00:1 must be refused at create: %d %s", rr.Code, rr.Body.String())
	}
}

// PoC3: markup in a URL path is refused; RFC 3986 paths are accepted.
func TestPoC3_URLPathIsRestrictedToRFC3986(t *testing.T) {
	p := DefaultTenantNetPolicy()
	refused := []string{
		"https://example.com/<img/src=x>/mcp",
		"https://example.com/a\"b/mcp",
		"https://example.com/`x`/mcp",
		"https://example.com/{x}/mcp",
		"https://example.com/a|b/mcp",
		"https://example.com/a\\b/mcp",
		"https://example.com/a%zz/mcp", // malformed escape
		"https://example.com/a%/mcp",   // truncated escape
	}
	for _, u := range refused {
		if _, err := ValidateTenantURL(u, p); err == nil {
			t.Errorf("ValidateTenantURL(%q) accepted; the path must be RFC 3986", u)
		}
	}
	accepted := []string{
		"https://example.com/metamcp/all/mcp",
		"https://example.com/a%20b/c~d_e-f.g",
		"https://example.com/x/y:z@w!$&'()*+,;=",
		"https://example.com:443/mcp",
	}
	for _, u := range accepted {
		if _, err := ValidateTenantURL(u, p); err != nil {
			t.Errorf("ValidateTenantURL(%q) refused: %v", u, err)
		}
	}
}

// PoC5: a tool-call connect error echoes the credential. It must be redacted.
func TestPoC5_ToolCallConnectErrorIsRedacted(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "victim", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": "Bearer " + pocToken},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	sess := fx.initSession("acme", keyA)
	fx.up.setBehaviour(func(u *fxUpstream) { u.rejectEcho = true })
	body := fx.mcp("acme", keyA, sess,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"victim__echo","arguments":{}}}`)
	if strings.Contains(body.Body.String(), pocToken) {
		t.Fatalf("tool-call error leaked the credential: %s", body.Body.String())
	}
	if !strings.Contains(body.Body.String(), maskPrefix+"7777") {
		t.Fatalf("expected the masked form in the error: %s", body.Body.String())
	}
}

// PoC5b (control): the /test path already redacts the credential.
func TestPoC5b_TestPathRedactsCredential(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "victim", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": "Bearer " + pocToken},
	})
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)
	fx.up.setBehaviour(func(u *fxUpstream) { u.rejectEcho = true })
	out := fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil)
	if strings.Contains(out.Body.String(), pocToken) {
		t.Fatal("test path leaked the credential")
	}
}

// PoC5 (JSON form): an upstream that echoes the credential inside a JSON body
// escapes it. The escaped form must be redacted too (P3).
func TestPoC5_JSONEscapedEchoIsRedacted(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	secret := `Bearer zq9Kx<&>"quote-7777`
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "victim", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": secret},
	})
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)
	fx.up.setBehaviour(func(u *fxUpstream) { u.rejectJSON = true })
	out := fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil)
	if strings.Contains(out.Body.String(), "zq9Kx") {
		t.Fatalf("JSON-escaped credential leaked: %s", out.Body.String())
	}
}

// PoC5 (order): the redaction must run before truncation. The credential below
// straddles the 300-byte cut, so a truncate-first pass leaves a prefix that
// matches nothing.
func TestPoC5_RedactionRunsBeforeTruncation(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	secret := "Bearer ZX81-secret-value-ABCDEFGHIJ"
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "victim", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": secret},
	})
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)
	fx.up.setBehaviour(func(u *fxUpstream) {
		u.errorBody = strings.Repeat("a", 290) + "ZX81-secret-value-ABCDEFGHIJ" + strings.Repeat("b", 50)
	})
	out := fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil)
	if strings.Contains(out.Body.String(), "ZX81-secre") {
		t.Fatalf("a truncated prefix of the credential leaked: %s", out.Body.String())
	}
}

// PoC7: the gateway's own names are never tenant upstreams.
func TestPoC7_GatewayOwnHostsAreRefused(t *testing.T) {
	p := NewTenantNetPolicy("mcp.subimpact.net")
	for _, u := range []string{
		"https://mcp.subimpact.net/metamcp/all/mcp",
		"https://subimpact.mcp.subimpact.net/metamcp/all/mcp",
		"https://app.subimpact.net/mcp",
		"https://x.app.subimpact.net/mcp",
	} {
		if _, err := ValidateTenantURL(u, p); err == nil {
			t.Errorf("ValidateTenantURL(%q) accepted; gateway hosts must be refused", u)
		}
	}
	if _, err := ValidateTenantURL("https://example.com/mcp", p); err != nil {
		t.Errorf("public host refused: %v", err)
	}
}

// PoC7 (create path): the fixture base host is refused at create.
func TestPoC7_BaseHostRefusedAtCreate(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "loop", "url": "https://" + fxBaseHost + "/metamcp/all/mcp",
		"headers": map[string]string{},
	})
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("the gateway base host must be refused at create: %d %s", rr.Code, rr.Body.String())
	}
}

// PoC8: one hostile upstream sends 50 pages of about 3 MiB. The aggregate must
// be capped: the list fails instead of growing without bound.
func TestPoC8_ToolsListAggregateIsCapped(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	blob := strings.Repeat("d", 1<<20)
	fx.up.setBehaviour(func(u *fxUpstream) {
		u.bigTools = func(cursor string) string {
			page, _ := strconv.Atoi(cursor)
			next := ""
			if page+1 < 50 {
				next = strconv.Itoa(page + 1)
			}
			var tools []string
			for i := 0; i < 3; i++ {
				tools = append(tools, fmt.Sprintf(`{"name":"t%d_%d","description":"%s","inputSchema":{"type":"object"}}`, page, i, blob))
			}
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"result":{"tools":[%s],"nextCursor":"%s"}}`, strings.Join(tools, ","), next)
		}
	})
	c := NewUpstreamClient(UpstreamConfig{Name: "hostile", URL: "https://" + fxUpstreamHost + "/mcp",
		Timeout: 20 * time.Second, Policy: fx.srv.agg.tenantPolicy})
	ctx := context.Background()
	if err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	tools, err := c.ListTools(ctx)
	if err == nil {
		t.Fatalf("a %d MiB tool list was accepted (%d tools)", 150, len(tools))
	}
	if len(tools) != 0 {
		t.Fatalf("a capped fetch must not return a partial list: %d tools", len(tools))
	}
}

// PoC8 (count and pages): a flood of small tools and too many pages are refused.
func TestPoC8_ToolCountAndPageCapsAreEnforced(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	page := func(n int, next string) func(string) string {
		return func(string) string {
			var tools []string
			for i := 0; i < n; i++ {
				tools = append(tools, fmt.Sprintf(`{"name":"t%d","inputSchema":{"type":"object"}}`, i))
			}
			return fmt.Sprintf(`{"jsonrpc":"2.0","id":2,"result":{"tools":[%s],"nextCursor":"%s"}}`, strings.Join(tools, ","), next)
		}
	}
	list := func(f func(string) string) ([]Tool, error) {
		fx.up.setBehaviour(func(u *fxUpstream) { u.bigTools = f })
		c := NewUpstreamClient(UpstreamConfig{Name: "flood", URL: "https://" + fxUpstreamHost + "/mcp",
			Timeout: 20 * time.Second, Policy: fx.srv.agg.tenantPolicy})
		ctx := context.Background()
		if err := c.Connect(ctx); err != nil {
			t.Fatal(err)
		}
		return c.ListTools(ctx)
	}
	if _, err := list(page(501, "")); err == nil {
		t.Fatal("501 tools in one fetch must be refused")
	}
	// Five pages of 100 tools, the last without a cursor: within both caps.
	fivePages := func(cursor string) string {
		p := 0
		if cursor != "" {
			p, _ = strconv.Atoi(cursor)
		}
		next := ""
		if p < 4 {
			next = strconv.Itoa(p + 1)
		}
		return page(100, next)(cursor)
	}
	tools, err := list(fivePages)
	if err != nil || len(tools) != 500 {
		t.Fatalf("five pages of 100 tools must succeed: %d tools, err=%v", len(tools), err)
	}
	// A sixth page is refused.
	six := func(cursor string) string {
		p := 0
		if cursor != "" {
			p, _ = strconv.Atoi(cursor)
		}
		return page(1, strconv.Itoa(p+1))(cursor) // never ends
	}
	if _, err := list(six); err == nil {
		t.Fatal("more than five pages must be refused")
	}
}

// PoC6 (deadline): a hung tenant upstream must not hold the request beyond the
// whole-request deadline.
func TestPoC6_TenantToolsListHasAWholeRequestDeadline(t *testing.T) {
	old := tenantRequestTimeout
	tenantRequestTimeout = 300 * time.Millisecond
	defer func() { tenantRequestTimeout = old }()

	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "tarpit", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	sess := fx.initSession("acme", keyA)
	fx.up.setBehaviour(func(u *fxUpstream) { u.hang = true })
	start := time.Now()
	fx.mcp("acme", keyA, sess, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("a hung tenant upstream held tools/list for %s", el)
	}
}

// Tenant API: the SSE transport is not offered to tenants (#16).
func TestTenantAPIRefusesSSEType(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "legacy", "url": "https://" + fxUpstreamHost + "/mcp", "type": "SSE",
		"headers": map[string]string{},
	})
	if rr.Code != http.StatusBadRequest || errCode(t, rr) != "invalid_type" {
		t.Fatalf("type SSE must be refused: %d %s", rr.Code, rr.Body.String())
	}
}

// Tenant test and refresh count against the trial daily cap (P3).
func TestTenantTestCountsAgainstTrialCap(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	future := time.Now().Add(24 * time.Hour)
	fx.db.addTenant("usertrial000000000000000000001", "trialer", "sk_sub_trial-key-0009", db.TenantTrialing, &future)
	rr := fx.api("sk_sub_trial-key-0009", "POST", "/api/tenant/servers", map[string]any{
		"name": "t", "url": "https://" + fxUpstreamHost + "/mcp", "headers": map[string]string{},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)
	fx.srv.tenants.trialDailyCap = 5
	fx.db.setUsageAllowed(false)
	before := fx.up.count()
	out := fx.api("sk_sub_trial-key-0009", "POST", "/api/tenant/servers/"+id+"/test", nil)
	if out.Code != http.StatusTooManyRequests {
		t.Fatalf("a test past the trial cap must be refused: %d %s", out.Code, out.Body.String())
	}
	if fx.up.count() != before {
		t.Fatal("a refused test must not contact the upstream")
	}
}
