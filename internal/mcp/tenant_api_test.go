package mcp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// --- in-memory store: implements every DB surface the tenant API touches ---

const (
	fxBaseHost     = "mcp.tenant-fixture.net"
	fxUpstreamHost = "upstream.tenant-fixture.net"
	fxUpstreamIP   = "93.184.216.34" // public: passes the production address rules
)

// Test-only credentials, built at runtime so no key-shaped literal sits in the
// source. They protect nothing outside these tests.
var (
	fxServiceToken = strings.Repeat("svc", 12) // 36 chars
	fxSecretKeyB64 = base64.StdEncoding.EncodeToString([]byte(strings.Repeat("T", 32)))
)

type fakeTenantDB struct {
	mu          sync.Mutex
	tenants     map[string]*db.Tenant
	endpoints   []*db.Endpoint
	keys        map[string]*db.APIKey
	servers     map[string]*db.MCPServer
	order       []string
	tools       map[string][]db.Tool
	mappings    map[string]db.NamespaceToolMapping // ns|toolUUID
	srvMap      map[string]db.ServerStatus         // ns|serverUUID
	seq         int
	bumps       int  // TryBumpUsage calls (trial cap accounting)
	usageDenied bool // TryBumpUsage refuses when set
	// beforeUpdate, when set, runs before UpdateTenantServer compares headers. A
	// test uses it to land a concurrent write between the handler's read and its
	// write (SaaS 4c, N5).
	beforeUpdate func()
}

func newFakeTenantDB() *fakeTenantDB {
	return &fakeTenantDB{
		tenants:  map[string]*db.Tenant{},
		keys:     map[string]*db.APIKey{},
		servers:  map[string]*db.MCPServer{},
		tools:    map[string][]db.Tool{},
		mappings: map[string]db.NamespaceToolMapping{},
		srvMap:   map[string]db.ServerStatus{},
	}
}

// uuidN returns a well-formed UUID for test id n.
func uuidN(n int) string { return fmt.Sprintf("00000000-0000-4000-8000-%012d", n) }

func (f *fakeTenantDB) newUUID() string {
	f.seq++
	return uuidN(f.seq)
}

func strp(s string) *string { return &s }

// --- EndpointStore ---

func (f *fakeTenantDB) GetEndpointByName(_ context.Context, name string) (*db.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.endpoints {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, nil
}

func (f *fakeTenantDB) GetEndpointByNameForUser(_ context.Context, name, userID string) (*db.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.endpoints {
		if e.Name == name && e.UserID != nil && *e.UserID == userID {
			return e, nil
		}
	}
	return nil, nil
}

func (f *fakeTenantDB) ListEndpoints(context.Context, *string) ([]db.Endpoint, error) {
	return nil, nil
}

func (f *fakeTenantDB) Ping(context.Context) error { return nil }

// --- KeyValidator ---

func (f *fakeTenantDB) ValidateAPIKey(_ context.Context, key string) (*db.APIKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[key], nil
}

// --- TenantStore / TenantServerStore ---

func (f *fakeTenantDB) GetTenantByUserID(_ context.Context, uid string) (*db.Tenant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tenants[uid], nil
}

func (f *fakeTenantDB) GetTenantBySlug(_ context.Context, slug string) (*db.Tenant, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tenants {
		if t.Slug == slug {
			return t, nil
		}
	}
	return nil, nil
}

func (f *fakeTenantDB) Entitlement(_ context.Context, t *db.Tenant) (*db.TenantEntitlement, error) {
	return db.EvaluateEntitlement(t, time.Now()), nil
}

func (f *fakeTenantDB) UsageToday(context.Context, string) (int64, error) { return 0, nil }
func (f *fakeTenantDB) BumpUsage(context.Context, string) error           { return nil }
func (f *fakeTenantDB) TryBumpUsage(context.Context, string, int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.bumps++
	return !f.usageDenied, nil
}

// setUsageAllowed controls whether TryBumpUsage grants the next reservation.
func (f *fakeTenantDB) setUsageAllowed(ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usageDenied = !ok
}

func (f *fakeTenantDB) TenantNamespaceUUID(_ context.Context, uid string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.endpoints {
		if e.Name == "all" && e.UserID != nil && *e.UserID == uid {
			return e.NamespaceUUID, nil
		}
	}
	return "", nil
}

// ownedBy mirrors the SQL scope: owner match AND tenant_managed. Legacy rows
// are never visible or writable through the tenant API.
func (f *fakeTenantDB) ownedBy(s *db.MCPServer, uid string) bool {
	return s.UserID != nil && *s.UserID == uid && s.TenantManaged
}

// ownedAny is the owner match alone (the name uniqueness index covers every row).
func (f *fakeTenantDB) ownedAny(s *db.MCPServer, uid string) bool {
	return s.UserID != nil && *s.UserID == uid
}

func (f *fakeTenantDB) ListTenantServers(_ context.Context, uid string) ([]db.TenantServerRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []db.TenantServerRow
	for _, id := range f.order {
		s := f.servers[id]
		if f.ownedBy(s, uid) {
			out = append(out, db.TenantServerRow{Server: *s, ToolCount: len(f.tools[id])})
		}
	}
	return out, nil
}

func (f *fakeTenantDB) CreateTenantServer(_ context.Context, uid, ns string, s *db.MCPServer, max int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	owned := 0
	for _, id := range f.order {
		o := f.servers[id]
		if f.ownedAny(o, uid) && o.Name == s.Name {
			return db.ErrTenantNameTaken
		}
		if f.ownedBy(o, uid) {
			owned++
		}
	}
	if owned >= max {
		return db.ErrTenantServerLimit
	}
	if s.UUID == "" { // the real store honours a caller-chosen id (sealed to it)
		s.UUID = f.newUUID()
	}
	s.CreatedAt = time.Now()
	s.ErrorStatus = db.ErrorStatusNone
	s.TenantManaged = true
	s.UserID = strp(uid)
	cp := *s
	f.servers[s.UUID] = &cp
	f.order = append(f.order, s.UUID)
	f.srvMap[ns+"|"+s.UUID] = db.ServerStatusActive
	return nil
}

func (f *fakeTenantDB) UpdateTenantServer(_ context.Context, uid string, s *db.MCPServer, expectedHeaders json.RawMessage) (bool, error) {
	if f.beforeUpdate != nil {
		f.beforeUpdate()
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.servers[s.UUID]
	if !ok || !f.ownedBy(cur, uid) {
		return false, nil
	}
	// Compare-and-set on the headers, as the database does.
	if !jsonEqual(cur.Headers, expectedHeaders) {
		return false, db.ErrTenantHeadersChanged
	}
	for _, id := range f.order {
		o := f.servers[id]
		if id != s.UUID && f.ownedAny(o, uid) && o.Name == s.Name {
			return false, db.ErrTenantNameTaken
		}
	}
	cur.Name = s.Name
	cur.Type = s.Type
	cur.URL = s.URL
	cur.Headers = s.Headers
	cur.TenantManaged = true
	cur.ErrorStatus = db.ErrorStatusNone
	cur.LastError = nil
	cur.LastCheckedAt = nil
	return true, nil
}

func (f *fakeTenantDB) DeleteTenantServer(_ context.Context, uid, uuid string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.servers[uuid]
	if !ok || !f.ownedBy(cur, uid) {
		return false, nil
	}
	// Cascade as the schema does: tools, mappings and namespace links.
	for _, t := range f.tools[uuid] {
		for k, m := range f.mappings {
			if m.ToolUUID == t.UUID {
				delete(f.mappings, k)
			}
		}
	}
	delete(f.tools, uuid)
	for k := range f.srvMap {
		if strings.HasSuffix(k, "|"+uuid) {
			delete(f.srvMap, k)
		}
	}
	delete(f.servers, uuid)
	kept := f.order[:0]
	for _, id := range f.order {
		if id != uuid {
			kept = append(kept, id)
		}
	}
	f.order = kept
	return true, nil
}

func (f *fakeTenantDB) ListTenantTools(_ context.Context, uid, ns string) ([]db.TenantToolRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []db.TenantToolRow
	for _, id := range f.order {
		s := f.servers[id]
		if !f.ownedBy(s, uid) {
			continue
		}
		for _, t := range f.tools[id] {
			out = append(out, f.toolRow(t, s, ns))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ServerName+out[i].ToolName < out[j].ServerName+out[j].ToolName })
	return out, nil
}

func (f *fakeTenantDB) toolRow(t db.Tool, s *db.MCPServer, ns string) db.TenantToolRow {
	status := db.ServerStatusActive
	if m, ok := f.mappings[ns+"|"+t.UUID]; ok {
		status = m.Status
	}
	return db.TenantToolRow{ToolUUID: t.UUID, ToolName: t.Name, Description: t.Description,
		ServerUUID: s.UUID, ServerName: s.Name, Status: status}
}

func (f *fakeTenantDB) GetTenantTool(_ context.Context, uid, toolUUID, ns string) (*db.TenantToolRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, id := range f.order {
		s := f.servers[id]
		if !f.ownedBy(s, uid) {
			continue
		}
		for _, t := range f.tools[id] {
			if t.UUID == toolUUID {
				r := f.toolRow(t, s, ns)
				return &r, nil
			}
		}
	}
	return nil, nil
}

func (f *fakeTenantDB) SetToolMappingStatus(_ context.Context, ns, toolUUID, serverUUID string, status db.ServerStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mappings[ns+"|"+toolUUID] = db.NamespaceToolMapping{
		UUID: f.newUUID(), NamespaceUUID: ns, ToolUUID: toolUUID, MCPServerUUID: serverUUID, Status: status,
	}
	return nil
}

// --- ToolStore (aggregator) ---

func (f *fakeTenantDB) GetActiveServersForNamespace(_ context.Context, ns string) ([]db.MCPServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []db.MCPServer
	for _, id := range f.order {
		if f.srvMap[ns+"|"+id] == db.ServerStatusActive {
			out = append(out, *f.servers[id])
		}
	}
	return out, nil
}

func (f *fakeTenantDB) GetToolMappings(_ context.Context, ns string) ([]struct {
	Mapping db.NamespaceToolMapping
	Tool    db.Tool
}, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []struct {
		Mapping db.NamespaceToolMapping
		Tool    db.Tool
	}
	for k, m := range f.mappings {
		if !strings.HasPrefix(k, ns+"|") {
			continue
		}
		for _, tools := range f.tools {
			for _, t := range tools {
				if t.UUID == m.ToolUUID {
					out = append(out, struct {
						Mapping db.NamespaceToolMapping
						Tool    db.Tool
					}{m, t})
				}
			}
		}
	}
	return out, nil
}

func (f *fakeTenantDB) SyncTools(_ context.Context, serverUUID string, in []db.SyncToolInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	existing := map[string]string{}
	for _, t := range f.tools[serverUUID] {
		existing[t.Name] = t.UUID
	}
	var next []db.Tool
	for _, t := range in {
		id := existing[t.Name]
		if id == "" {
			id = f.newUUID()
		}
		desc := t.Description
		next = append(next, db.Tool{UUID: id, Name: t.Name, Description: &desc,
			ToolSchema: t.InputSchema, MCPServerUUID: serverUUID})
	}
	f.tools[serverUUID] = next
	return nil
}

func (f *fakeTenantDB) SetServerErrorStatus(_ context.Context, uuid string, status db.ErrorStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.servers[uuid]; ok {
		s.ErrorStatus = status
	}
	return nil
}

// SetServerCheck is the optional capability behind recordCheck.
func (f *fakeTenantDB) SetServerCheck(_ context.Context, uuid string, lastError *string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s, ok := f.servers[uuid]; ok {
		s.LastError = lastError
		now := time.Now()
		s.LastCheckedAt = &now
	}
	return nil
}

// addTenant registers a tenant, its "all" endpoint and namespace, and one key.
func (f *fakeTenantDB) addTenant(uid, slug, key string, status db.TenantStatus, trialEnd *time.Time) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &db.Tenant{ID: "tid-" + uid, UserID: uid, Slug: slug, Status: status, Plan: "pro", TrialEndsAt: trialEnd}
	f.tenants[uid] = t
	ns := f.newUUID()
	f.endpoints = append(f.endpoints, &db.Endpoint{UUID: f.newUUID(), Name: "all", NamespaceUUID: ns,
		EnableAPIKeyAuth: true, UserID: strp(uid)})
	f.keys[key] = &db.APIKey{UUID: f.newUUID(), Name: "default", Key: "stored", UserID: strp(uid), IsActive: true}
	return ns
}

// addRawServer inserts a row directly (operator or NULL-owner rows).
func (f *fakeTenantDB) addRawServer(s db.MCPServer, ns string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	s.UUID = f.newUUID()
	s.CreatedAt = time.Now()
	if len(s.Headers) == 0 {
		s.Headers = json.RawMessage(`{}`)
	}
	cp := s
	f.servers[s.UUID] = &cp
	f.order = append(f.order, s.UUID)
	if ns != "" {
		f.srvMap[ns+"|"+s.UUID] = db.ServerStatusActive
	}
	return s.UUID
}

// setTrial moves a tenant's trial (used to make a tenant inactive).
func (f *fakeTenantDB) setTrial(uid string, end time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tenants[uid].TrialEndsAt = &end
}

// --- upstream MCP server (TLS) ---

type fxUpstream struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls int
	auth  []string
	hosts []string // Host header of each request
	// rejectEcho makes every request fail with 401 and echo the Authorization
	// value, as some upstreams do. rejectJSON echoes it JSON-escaped.
	rejectEcho bool
	rejectJSON bool
	// hang blocks each request until the client gives up (deadline tests).
	hang bool
	// bigTools, when set, replaces the tools/list answer with this function's
	// output for the page cursor (aggregate-cap tests).
	bigTools func(cursor string) (body string)
	// errorBody is returned with HTTP 500 when set (redaction tests).
	errorBody string
	// stop releases handlers that are still blocked when the test ends.
	stop chan struct{}
}

func (u *fxUpstream) setBehaviour(f func(*fxUpstream)) {
	u.mu.Lock()
	defer u.mu.Unlock()
	f(u)
}

func (u *fxUpstream) lastHost() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.hosts) == 0 {
		return ""
	}
	return u.hosts[len(u.hosts)-1]
}

func newFxUpstream(t *testing.T) *fxUpstream {
	t.Helper()
	u := &fxUpstream{stop: make(chan struct{})}
	u.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.calls++
		u.auth = append(u.auth, r.Header.Get("Authorization"))
		u.hosts = append(u.hosts, r.Host)
		rejectEcho, rejectJSON, hang := u.rejectEcho, u.rejectJSON, u.hang
		bigTools, errorBody := u.bigTools, u.errorBody
		u.mu.Unlock()
		if hang {
			select {
			case <-r.Context().Done():
			case <-u.stop:
			}
			return
		}
		if rejectEcho || rejectJSON {
			w.WriteHeader(http.StatusUnauthorized)
			if rejectJSON {
				enc, _ := json.Marshal(r.Header.Get("Authorization"))
				fmt.Fprintf(w, `{"error":"token rejected: %s"}`, enc[1:len(enc)-1])
				return
			}
			fmt.Fprintf(w, "token rejected: %s", r.Header.Get("Authorization"))
			return
		}
		if errorBody != "" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, errorBody)
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "up-1")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{}},"serverInfo":{"name":"fixture","version":"1"}}}`, req.ID)
		case "tools/list":
			if bigTools != nil {
				fmt.Fprint(w, bigTools(req.Params.Cursor))
				return
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"echo","description":"Echo","inputSchema":{"type":"object"}},{"name":"add","description":"Add","inputSchema":{"type":"object"}}]}}`, req.ID)
		case "tools/call":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"upstream-said-hi"}]}}`, req.ID)
		default:
			w.WriteHeader(http.StatusAccepted)
		}
	}))
	t.Cleanup(u.srv.Close)
	// Cleanups run last-in first-out: release blocked handlers before Close waits
	// for them.
	t.Cleanup(func() { close(u.stop) })
	return u
}

func (u *fxUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.calls
}

func (u *fxUpstream) lastAuth() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.auth) == 0 {
		return ""
	}
	return u.auth[len(u.auth)-1]
}

// --- fixture: the real Server, Aggregator, Pool and tenant API ---

type tenantFixture struct {
	t        *testing.T
	db       *fakeTenantDB
	srv      *Server
	public   http.Handler
	internal http.Handler
	up       *fxUpstream
}

// newTenantFixture wires the production code. Only three things are test
// substitutes: DNS answers for fixture names, the final TCP dial of the public
// fixture address (redirected to the local TLS server), and the trust roots.
// The address rules, port rule, scheme rule, redirect refusal and everything
// above them are the production code.
func newTenantFixture(t *testing.T, maxServers int) *tenantFixture {
	t.Helper()
	up := newFxUpstream(t)
	pool := x509.NewCertPool()
	pool.AddCert(up.srv.Certificate())
	// Production rules (address policy, deny-list, port, scheme) come from
	// NewTenantNetPolicy, as in main. Only DNS, the final dial and the trust roots
	// are substituted.
	policy := NewTenantNetPolicy(fxBaseHost)
	policy.Lookup = fakeResolver{
		fxUpstreamHost:              {fxUpstreamIP},
		"loop.tenant-fixture.net":   {"127.0.0.1"},
		"rebind.tenant-fixture.net": {"10.0.5.2"},
		"mixed.tenant-fixture.net":  {fxUpstreamIP, "192.168.1.10"},
		"meta.tenant-fixture.net":   {"169.254.169.254"},
		"cgnat.tenant-fixture.net":  {"100.100.100.100"},
		// Regression fixtures (SaaS phase 4b PoCs). The base host resolves to a
		// public address, so only the deny-list can refuse it.
		"attacker.tenant-fixture.net": {fxUpstreamIP},
		"v6.tenant-fixture.net":       {"::7f00:1"},
		fxBaseHost:                    {fxUpstreamIP},
	}.lookup
	policy.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == fxUpstreamIP+":443" {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", up.srv.Listener.Addr().String())
		}
		return nil, fmt.Errorf("test dialer: unexpected dial to %s", addr)
	}
	policy.TLS = &tls.Config{RootCAs: pool, ServerName: "example.com"}
	fdb := newFakeTenantDB()
	box, err := NewSecretBox(fxSecretKeyB64)
	if err != nil {
		t.Fatal(err)
	}
	agg := NewAggregatorWithSSRF(NewPool(50, 20, time.Minute), fdb, NewSSRFGuard(true))
	agg.SetTenantUpstreams(box, policy)
	srv := NewServer(fdb, agg, NewPool(50, 20, time.Minute), NewAuth(fdb), time.Hour)
	srv.EnableTenants(fdb, fxBaseHost, 0)
	if err := srv.EnableTenantAPI(fdb, TenantAPIConfig{ServiceToken: fxServiceToken, MaxServers: maxServers, TestPerMinute: 600}); err != nil {
		t.Fatal(err)
	}
	return &tenantFixture{t: t, db: fdb, srv: srv, public: srv.TenantAPIHandler(), internal: srv.TenantAPIInternalHandler(), up: up}
}

// api sends one request to the public tenant API with an X-API-Key.
func (fx *tenantFixture) api(key, method, path string, body any) *httptest.ResponseRecorder {
	return fx.send(fx.public, method, path, key, body, nil)
}

// svc sends one request to the internal listener with service auth.
func (fx *tenantFixture) svc(uid, method, path string, body any) *httptest.ResponseRecorder {
	return fx.send(fx.internal, method, path, "", body, map[string]string{
		tenantServiceTokenHeader: fxServiceToken,
		tenantUserHeader:         uid,
	})
}

func (fx *tenantFixture) send(h http.Handler, method, path, key string, body any, extra map[string]string) *httptest.ResponseRecorder {
	fx.t.Helper()
	var rd io.Reader
	if body != nil {
		raw, ok := body.(string)
		if !ok {
			b, err := json.Marshal(body)
			if err != nil {
				fx.t.Fatal(err)
			}
			raw = string(b)
		}
		rd = strings.NewReader(raw)
	}
	req := httptest.NewRequest(method, "https://"+fxBaseHost+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("X-API-Key", key)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// mcp posts one JSON-RPC message to a tenant endpoint on its subdomain.
func (fx *tenantFixture) mcp(slug, key, session, body string) *httptest.ResponseRecorder {
	fx.t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://"+slug+"."+fxBaseHost+"/metamcp/all/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("X-API-Key", key)
	if session != "" {
		req.Header.Set("mcp-session-id", session)
	}
	rr := httptest.NewRecorder()
	fx.srv.Handler().ServeHTTP(rr, req)
	return rr
}

// initSession opens an MCP session on a tenant endpoint and returns its id.
func (fx *tenantFixture) initSession(slug, key string) string {
	fx.t.Helper()
	rr := fx.mcp(slug, key, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}`)
	if rr.Code != http.StatusOK {
		fx.t.Fatalf("initialize %s: %d %s", slug, rr.Code, rr.Body.String())
	}
	return rr.Header().Get("mcp-session-id")
}

// rpcResult extracts the result object from an SSE or JSON JSON-RPC response.
func rpcResult(t *testing.T, body string) map[string]any {
	t.Helper()
	payload := body
	if i := strings.Index(body, "data: "); i >= 0 {
		payload = strings.TrimSpace(strings.SplitN(body[i+len("data: "):], "\n", 2)[0])
	}
	var msg struct {
		Result map[string]any `json:"result"`
		Error  map[string]any `json:"error"`
	}
	if err := json.Unmarshal([]byte(payload), &msg); err != nil {
		t.Fatalf("not JSON-RPC: %v (%s)", err, body)
	}
	if msg.Error != nil {
		t.Fatalf("rpc error: %v", msg.Error)
	}
	return msg.Result
}

func toolNames(t *testing.T, result map[string]any) []string {
	t.Helper()
	raw, _ := result["tools"].([]any)
	var out []string
	for _, x := range raw {
		out = append(out, x.(map[string]any)["name"].(string))
	}
	sort.Strings(out)
	return out
}

// decode parses a JSON response body into a generic map.
func decode(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%d): %v: %s", rr.Code, err, rr.Body.String())
	}
	return out
}

func errCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	m := decode(t, rr)
	s, _ := m["error"].(string)
	return s
}

// --- tests ---

const (
	keyA     = "sk_sub_tenant-a-key-0001"
	keyB     = "sk_sub_tenant-b-key-0002"
	keyC     = "sk_sub_tenant-c-key-0003"
	keyAdmin = "sk_admin_operator-key-9999"
	keyOpNon = "sk_mt_operator-nonadmin-8888"
	userA    = "usera00000000000000000000000001"
	userB    = "userb00000000000000000000000002"
	userC    = "userc00000000000000000000000003"
	userOp   = "7wtNrrYPNbx9DBO6TXMGYrcX5dJkR2iT"
)

// standardFixture: tenants A (active), B (active), C (trial over), the
// operator (active) with a server, and a NULL-owner legacy row.
func standardFixture(t *testing.T, maxServers int) (*tenantFixture, string, string, string, string) {
	t.Helper()
	fx := newTenantFixture(t, maxServers)
	nsA := fx.db.addTenant(userA, "acme", keyA, db.TenantActive, nil)
	nsB := fx.db.addTenant(userB, "beta", keyB, db.TenantActive, nil)
	// C starts with a live trial; tests that need it inactive lapse it.
	future := time.Now().Add(24 * time.Hour)
	nsC := fx.db.addTenant(userC, "gone", keyC, db.TenantTrialing, &future)
	nsOp := fx.db.addTenant(userOp, "subimpact", "unused-op-key", db.TenantActive, nil)
	fx.db.keys[keyAdmin] = &db.APIKey{UUID: "k-admin", Name: "hermes", IsAdmin: true, UserID: strp(userOp), IsActive: true}
	fx.db.keys[keyOpNon] = &db.APIKey{UUID: "k-opn", Name: "gemini", IsAdmin: false, UserID: strp(userOp), IsActive: true}
	fx.db.keys["sk_orphan"] = &db.APIKey{UUID: "k-orphan", Name: "orphan", IsActive: true}
	// Operator upstream: owned by the operator, legacy (plaintext) row.
	fx.db.addRawServer(db.MCPServer{Name: "opsrv", Type: db.ServerTypeStreamableHTTP,
		URL: strp("https://" + fxUpstreamHost + "/mcp"), UserID: strp(userOp),
		Headers: json.RawMessage(`{"Authorization":"Bearer operator-secret-AAAA"}`)}, nsOp)
	// NULL-owner legacy row, not mapped anywhere.
	fx.db.addRawServer(db.MCPServer{Name: "nullrow", Type: db.ServerTypeStreamableHTTP,
		URL: strp("https://" + fxUpstreamHost + "/null")}, "")
	return fx, nsA, nsB, nsC, nsOp
}

func TestTenantAPIAuthShapes(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	cases := []struct {
		name string
		rr   *httptest.ResponseRecorder
		code int
		err  string
	}{
		{"public: no key", fx.send(fx.public, "GET", "/api/tenant/servers", "", nil, nil), 401, "authentication_required"},
		{"public: unknown key", fx.api("sk_nope", "GET", "/api/tenant/servers", nil), 401, "invalid_api_key"},
		{"public: admin key refused", fx.api(keyAdmin, "GET", "/api/tenant/servers", nil), 403, "key_not_allowed"},
		{"public: unowned key refused", fx.api("sk_orphan", "GET", "/api/tenant/servers", nil), 403, "key_not_allowed"},
		{"public: tenant key ok", fx.api(keyA, "GET", "/api/tenant/servers", nil), 200, ""},
		{"public: service headers are ignored", fx.send(fx.public, "GET", "/api/tenant/servers", "", nil, map[string]string{
			tenantServiceTokenHeader: fxServiceToken, tenantUserHeader: userA}), 401, "authentication_required"},
		{"internal: no token", fx.send(fx.internal, "GET", "/api/tenant/servers", "", nil, map[string]string{tenantUserHeader: userA}), 401, "service_auth_failed"},
		{"internal: wrong token", fx.send(fx.internal, "GET", "/api/tenant/servers", "", nil, map[string]string{tenantServiceTokenHeader: "nope", tenantUserHeader: userA}), 401, "service_auth_failed"},
		{"internal: API key is not service auth", fx.send(fx.internal, "GET", "/api/tenant/servers", keyA, nil, nil), 401, "service_auth_failed"},
		{"internal: user header missing", fx.send(fx.internal, "GET", "/api/tenant/servers", "", nil, map[string]string{tenantServiceTokenHeader: fxServiceToken}), 400, "tenant_user_required"},
		{"internal: malformed user", fx.send(fx.internal, "GET", "/api/tenant/servers", "", nil, map[string]string{tenantServiceTokenHeader: fxServiceToken, tenantUserHeader: "a b;c"}), 400, "tenant_user_required"},
		{"internal: unknown tenant", fx.svc("nobody000000000000000000000000ff", "GET", "/api/tenant/servers", nil), 403, "no_tenant"},
		{"internal: tenant ok", fx.svc(userA, "GET", "/api/tenant/servers", nil), 200, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.rr.Code != c.code {
				t.Fatalf("status = %d, want %d: %s", c.rr.Code, c.code, c.rr.Body.String())
			}
			if c.err != "" && errCode(t, c.rr) != c.err {
				t.Fatalf("error = %q, want %q", errCode(t, c.rr), c.err)
			}
		})
	}
}

func TestTenantListHidesOtherTenantsAndOperatorRows(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{"name": "mine", "url": "https://" + fxUpstreamHost + "/mcp"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	mine := decode(t, rr)["server"].(map[string]any)["id"].(string)

	list := decode(t, fx.api(keyA, "GET", "/api/tenant/servers", nil))
	servers := list["servers"].([]any)
	if len(servers) != 1 || servers[0].(map[string]any)["id"] != mine {
		t.Fatalf("A sees %v, want only its own server", servers)
	}
	if strings.Contains(fx.api(keyA, "GET", "/api/tenant/servers", nil).Body.String(), "operator") {
		t.Fatal("operator rows leaked into a tenant list")
	}
	if list["endpoint_url"] != "https://acme."+fxBaseHost+"/metamcp/all/mcp" {
		t.Fatalf("endpoint_url = %v", list["endpoint_url"])
	}

	// B sees nothing; B cannot read A's, the operator's or the NULL-owner row by id.
	if got := decode(t, fx.api(keyB, "GET", "/api/tenant/servers", nil))["servers"].([]any); len(got) != 0 {
		t.Fatalf("B sees %v", got)
	}
	opID := ""
	for _, id := range fx.db.order {
		if fx.db.servers[id].Name == "opsrv" {
			opID = id
		}
	}
	nullID := ""
	for _, id := range fx.db.order {
		if fx.db.servers[id].Name == "nullrow" {
			nullID = id
		}
	}
	// Every other tenant gets 404 for A's server, the operator's row and the
	// NULL-owner row alike.
	for _, id := range []string{mine, opID, nullID} {
		for _, key := range []string{keyB, keyC} {
			if rr := fx.api(key, "GET", "/api/tenant/servers/"+id, nil); rr.Code != http.StatusNotFound {
				t.Fatalf("other tenant reads server %s: %d", id, rr.Code)
			}
		}
	}
}

func TestTenantCannotModifyOthersServers(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	mine := decode(t, fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "shared-name", "url": "https://" + fxUpstreamHost + "/mcp"}))["server"].(map[string]any)["id"].(string)
	before := fx.up.count()

	// B's attempts against A's server, its tool, and the operator's row: all 404.
	paths := []struct {
		method, path string
		body         any
	}{
		{"PATCH", "/api/tenant/servers/" + mine, map[string]any{"name": "hijacked"}},
		{"DELETE", "/api/tenant/servers/" + mine, nil},
		{"POST", "/api/tenant/servers/" + mine + "/test", nil},
		{"POST", "/api/tenant/servers/" + mine + "/refresh", nil},
	}
	for _, p := range paths {
		if rr := fx.api(keyB, p.method, p.path, p.body); rr.Code != http.StatusNotFound {
			t.Fatalf("%s %s by B = %d, want 404: %s", p.method, p.path, rr.Code, rr.Body.String())
		}
	}
	if fx.up.count() != before {
		t.Fatal("B's test of A's server reached the upstream")
	}
	// A's server is unchanged.
	if fx.db.servers[mine].Name != "shared-name" {
		t.Fatalf("A's server was renamed by B: %s", fx.db.servers[mine].Name)
	}
	if _, ok := fx.db.servers[mine]; !ok {
		t.Fatal("A's server was deleted by B")
	}
	// Bad ids are 404 and never reach the database as a malformed uuid.
	if rr := fx.api(keyA, "GET", "/api/tenant/servers/not-a-uuid", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("malformed id = %d", rr.Code)
	}
}

func TestTenantRejectsSTDIOSSRFAndInjectionWithoutConnecting(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	before := fx.up.count()
	bad := []struct {
		name string
		body any
	}{
		{"stdio", map[string]any{"name": "x", "url": "https://" + fxUpstreamHost + "/mcp", "type": "STDIO"}},
		{"stdio lowercase", map[string]any{"name": "x", "url": "https://" + fxUpstreamHost + "/mcp", "type": "stdio"}},
		{"streamable lowercase", map[string]any{"name": "x", "url": "https://" + fxUpstreamHost + "/mcp", "type": "streamable_http"}},
		{"command smuggled", `{"name":"x","url":"https://` + fxUpstreamHost + `/mcp","command":"sh","args":["-c","id"]}`},
		{"env smuggled", `{"name":"x","url":"https://` + fxUpstreamHost + `/mcp","env":{"A":"B"}}`},
		{"http scheme", map[string]any{"name": "x", "url": "http://" + fxUpstreamHost + "/mcp"}},
		{"loopback literal", map[string]any{"name": "x", "url": "https://127.0.0.1/mcp"}},
		{"private literal", map[string]any{"name": "x", "url": "https://10.0.5.2:5432"}},
		{"metadata literal", map[string]any{"name": "x", "url": "https://169.254.169.254/"}},
		{"cgnat literal", map[string]any{"name": "x", "url": "https://100.100.100.100"}},
		{"ipv6 loopback", map[string]any{"name": "x", "url": "https://[::1]/"}},
		{"docker service name", map[string]any{"name": "x", "url": "https://submcp-saas:12011"}},
		{"dns to loopback", map[string]any{"name": "x", "url": "https://loop.tenant-fixture.net/mcp"}},
		{"dns to private", map[string]any{"name": "x", "url": "https://rebind.tenant-fixture.net/mcp"}},
		{"dns mixed answers", map[string]any{"name": "x", "url": "https://mixed.tenant-fixture.net/mcp"}},
		{"dns metadata", map[string]any{"name": "x", "url": "https://meta.tenant-fixture.net/"}},
		{"dns cgnat", map[string]any{"name": "x", "url": "https://cgnat.tenant-fixture.net/"}},
		{"credentials in url", map[string]any{"name": "x", "url": "https://u:p@" + fxUpstreamHost + "/mcp"}},
		{"token in query", map[string]any{"name": "x", "url": "https://" + fxUpstreamHost + "/mcp?token=abc"}},
		{"port 8443", map[string]any{"name": "x", "url": "https://" + fxUpstreamHost + ":8443/mcp"}},
		{"bad name", map[string]any{"name": "a__b", "url": "https://" + fxUpstreamHost + "/mcp"}},
		{"forbidden header host", map[string]any{"name": "x", "url": "https://" + fxUpstreamHost + "/mcp", "headers": map[string]string{"Host": "evil"}}},
		{"header injection", map[string]any{"name": "x", "url": "https://" + fxUpstreamHost + "/mcp", "headers": map[string]string{"X-A": "v\r\nInjected: 1"}}},
		{"masked value on create", map[string]any{"name": "x", "url": "https://" + fxUpstreamHost + "/mcp", "headers": map[string]string{"Authorization": "••••••••abcd"}}},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			rr := fx.api(keyA, "POST", "/api/tenant/servers", c.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
			}
		})
	}
	if fx.up.count() != before {
		t.Fatalf("refused servers reached the upstream (%d -> %d)", before, fx.up.count())
	}
	if n := len(decode(t, fx.api(keyA, "GET", "/api/tenant/servers", nil))["servers"].([]any)); n != 0 {
		t.Fatalf("refused servers were stored: %d", n)
	}
}

func TestTenantStoresCredentialsSealedAndMasked(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "secure", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": "Bearer tenant-live-token-7777"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "tenant-live-token") {
		t.Fatal("create response returned the full credential")
	}
	if !strings.Contains(rr.Body.String(), maskPrefix+"7777") {
		t.Fatalf("create response should show the masked value: %s", rr.Body.String())
	}
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)

	// Row at rest: sealed, never plaintext.
	stored := string(fx.db.servers[id].Headers)
	if strings.Contains(stored, "tenant-live-token") || !strings.Contains(stored, "enc:v2:") {
		t.Fatalf("stored headers = %s", stored)
	}
	// Every read path masks.
	for _, body := range []string{
		fx.api(keyA, "GET", "/api/tenant/servers", nil).Body.String(),
		fx.api(keyA, "GET", "/api/tenant/servers/"+id, nil).Body.String(),
		fx.svc(userA, "GET", "/api/tenant/servers", nil).Body.String(),
	} {
		if strings.Contains(body, "tenant-live-token") {
			t.Fatalf("a read path returned the credential: %s", body)
		}
	}
}

func TestTenantLimitsAndNames(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 2)
	mk := func(name string) *httptest.ResponseRecorder {
		return fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{"name": name, "url": "https://" + fxUpstreamHost + "/mcp"})
	}
	if rr := mk("one"); rr.Code != http.StatusCreated {
		t.Fatalf("first: %d", rr.Code)
	}
	if rr := mk("one"); rr.Code != http.StatusConflict || errCode(t, rr) != "name_taken" {
		t.Fatalf("duplicate name: %d %s", rr.Code, rr.Body.String())
	}
	if rr := mk("two"); rr.Code != http.StatusCreated {
		t.Fatalf("second: %d", rr.Code)
	}
	rr := mk("three")
	if rr.Code != http.StatusConflict || errCode(t, rr) != "server_limit_reached" {
		t.Fatalf("third must hit the limit: %d %s", rr.Code, rr.Body.String())
	}
	// Another tenant has its own quota.
	if rr := fx.api(keyB, "POST", "/api/tenant/servers", map[string]any{"name": "one", "url": "https://" + fxUpstreamHost + "/mcp"}); rr.Code != http.StatusCreated {
		t.Fatalf("B's quota must be independent: %d %s", rr.Code, rr.Body.String())
	}
	for _, bad := range []string{"", "a b", "under_score", "-leading", strings.Repeat("x", 41)} {
		if rr := mk(bad); rr.Code != http.StatusBadRequest {
			t.Fatalf("name %q = %d, want 400", bad, rr.Code)
		}
	}
	tooMany := map[string]string{}
	for i := 0; i < 11; i++ {
		tooMany[fmt.Sprintf("X-H%d", i)] = "v"
	}
	if rr := fx.api(keyB, "POST", "/api/tenant/servers", map[string]any{"name": "h", "url": "https://" + fxUpstreamHost + "/mcp", "headers": tooMany}); rr.Code != http.StatusBadRequest {
		t.Fatalf("11 headers = %d", rr.Code)
	}
	long := strings.Repeat("v", 4097)
	if rr := fx.api(keyB, "POST", "/api/tenant/servers", map[string]any{"name": "h2", "url": "https://" + fxUpstreamHost + "/mcp", "headers": map[string]string{"X-Long": long}}); rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized header = %d", rr.Code)
	}
	if rr := fx.api(keyB, "POST", "/api/tenant/servers", strings.Repeat("{", 20000)); rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized body = %d", rr.Code)
	}
}

// The core flow: create, test, then the tenant endpoint serves the tools and a
// tools/call reaches the upstream with the stored credential, all without a
// restart. Another tenant's endpoint shows none of them.
func TestTenantServerAppearsOnItsEndpointAndIsIsolated(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "fixture", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": "Bearer fixture-token-AB12"},
	})
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)

	// Run the explicit test first: it stores the tools and primes the cache.
	tr := decode(t, fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil))
	if tr["ok"] != true || tr["tool_count"] != float64(2) {
		t.Fatalf("test = %v", tr)
	}
	if fx.up.lastAuth() != "Bearer fixture-token-AB12" {
		t.Fatalf("upstream got Authorization %q", fx.up.lastAuth())
	}

	session := fx.initSession("acme", keyA)
	list := rpcResult(t, fx.mcp("acme", keyA, session, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`).Body.String())
	if got := toolNames(t, list); strings.Join(got, ",") != "fixture__add,fixture__echo" {
		t.Fatalf("tenant tools = %v", got)
	}
	call := fx.mcp("acme", keyA, session, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fixture__echo","arguments":{"text":"hi"}}}`)
	if !strings.Contains(call.Body.String(), "upstream-said-hi") {
		t.Fatalf("tools/call failed: %s", call.Body.String())
	}

	// Tenant B: its own endpoint is empty and it cannot call A's tools.
	sessionB := fx.initSession("beta", keyB)
	emptyB := rpcResult(t, fx.mcp("beta", keyB, sessionB, `{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`).Body.String())
	if got := toolNames(t, emptyB); len(got) != 0 {
		t.Fatalf("B's endpoint shows %v", got)
	}
	if strings.Contains(fx.mcp("beta", keyB, sessionB, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"fixture__echo","arguments":{}}}`).Body.String(), "upstream-said-hi") {
		t.Fatal("B reached A's upstream through its endpoint")
	}
	// The circuit breaker stayed closed through the whole flow.
	if got := fx.db.servers[id].ErrorStatus; got != db.ErrorStatusNone {
		t.Fatalf("A's server error_status = %s", got)
	}
}

func TestTenantDeleteAndReAddTakeEffectWithoutRestart(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	id := decode(t, fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "fixture", "url": "https://" + fxUpstreamHost + "/mcp"}))["server"].(map[string]any)["id"].(string)
	fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil)
	session := fx.initSession("acme", keyA)
	before := toolNames(t, rpcResult(t, fx.mcp("acme", keyA, session, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`).Body.String()))
	if len(before) != 2 {
		t.Fatalf("before delete: %v", before)
	}

	if rr := fx.api(keyA, "DELETE", "/api/tenant/servers/"+id, nil); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	after := toolNames(t, rpcResult(t, fx.mcp("acme", keyA, session, `{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}`).Body.String()))
	if len(after) != 0 {
		t.Fatalf("deleted server still listed: %v", after)
	}
	if len(fx.db.tools[id]) != 0 {
		t.Fatal("tools of a deleted server remain")
	}
	// Re-add: appears again on the same endpoint.
	id2 := decode(t, fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "fixture", "url": "https://" + fxUpstreamHost + "/mcp"}))["server"].(map[string]any)["id"].(string)
	fx.api(keyA, "POST", "/api/tenant/servers/"+id2+"/refresh", nil)
	again := toolNames(t, rpcResult(t, fx.mcp("acme", keyA, session, `{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`).Body.String()))
	if len(again) != 2 {
		t.Fatalf("re-added server not visible: %v", again)
	}
}

func TestTenantToolToggleHidesAndBlocksTool(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	id := decode(t, fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "fixture", "url": "https://" + fxUpstreamHost + "/mcp"}))["server"].(map[string]any)["id"].(string)
	fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil)

	tools := decode(t, fx.api(keyA, "GET", "/api/tenant/tools", nil))["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tenant tools = %d", len(tools))
	}
	var addID string
	for _, x := range tools {
		m := x.(map[string]any)
		if m["name"] == "fixture__add" {
			addID = m["id"].(string)
		}
	}
	// B cannot toggle A's tool.
	if rr := fx.api(keyB, "PATCH", "/api/tenant/tools/"+addID, map[string]any{"enabled": false}); rr.Code != http.StatusNotFound {
		t.Fatalf("B toggles A's tool: %d", rr.Code)
	}
	if rr := fx.api(keyA, "PATCH", "/api/tenant/tools/"+addID, map[string]any{}); rr.Code != http.StatusBadRequest {
		t.Fatalf("missing enabled = %d", rr.Code)
	}
	if rr := fx.api(keyA, "PATCH", "/api/tenant/tools/"+addID, map[string]any{"enabled": false}); rr.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rr.Code, rr.Body.String())
	}

	session := fx.initSession("acme", keyA)
	listed := toolNames(t, rpcResult(t, fx.mcp("acme", keyA, session, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`).Body.String()))
	if strings.Join(listed, ",") != "fixture__echo" {
		t.Fatalf("disabled tool still listed: %v", listed)
	}
	blocked := fx.mcp("acme", keyA, session, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fixture__add","arguments":{}}}`)
	if !strings.Contains(blocked.Body.String(), "disabled") || strings.Contains(blocked.Body.String(), "upstream-said-hi") {
		t.Fatalf("disabled tool was callable: %s", blocked.Body.String())
	}

	fx.api(keyA, "PATCH", "/api/tenant/tools/"+addID, map[string]any{"enabled": true})
	listed = toolNames(t, rpcResult(t, fx.mcp("acme", keyA, session, `{"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}}`).Body.String()))
	if strings.Join(listed, ",") != "fixture__add,fixture__echo" {
		t.Fatalf("re-enabled tool missing: %v", listed)
	}
}

func TestTenantUpdateKeepsStoredCredentialForMaskedValue(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	id := decode(t, fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "fixture", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": "Bearer keep-me-WXYZ"},
	}))["server"].(map[string]any)["id"].(string)

	// Editing the name while sending the mask back keeps the credential.
	rr := fx.api(keyA, "PATCH", "/api/tenant/servers/"+id, map[string]any{
		"name":    "renamed",
		"headers": map[string]string{"Authorization": maskPrefix + "WXYZ"},
	})
	if rr.Code != http.StatusOK {
		t.Fatalf("patch: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "keep-me") {
		t.Fatal("patch response leaked the credential")
	}
	fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil)
	if fx.up.lastAuth() != "Bearer keep-me-WXYZ" {
		t.Fatalf("masked edit changed the credential: upstream got %q", fx.up.lastAuth())
	}

	// A mask that does not match is refused and changes nothing.
	if rr := fx.api(keyA, "PATCH", "/api/tenant/servers/"+id, map[string]any{
		"headers": map[string]string{"Authorization": maskPrefix + "0000"}}); rr.Code != http.StatusBadRequest {
		t.Fatalf("wrong mask = %d", rr.Code)
	}
	// Changing the URL clears the old check result.
	fx.api(keyA, "PATCH", "/api/tenant/servers/"+id, map[string]any{"url": "https://" + fxUpstreamHost + "/v2/mcp"})
	if fx.db.servers[id].LastCheckedAt != nil {
		t.Fatal("URL change must clear the last check")
	}
	if rr := fx.api(keyA, "PATCH", "/api/tenant/servers/"+id, map[string]any{"url": "http://" + fxUpstreamHost}); rr.Code != http.StatusBadRequest {
		t.Fatalf("PATCH to http = %d", rr.Code)
	}
}

func TestTenantInactiveCanViewButNotAddOrTest(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	// Create while active, then let the trial lapse.
	id := decode(t, fx.api(keyC, "POST", "/api/tenant/servers", map[string]any{
		"name": "before", "url": "https://" + fxUpstreamHost + "/mcp"}))["server"].(map[string]any)["id"].(string)
	fx.db.setTrial(userC, time.Now().Add(-time.Minute))

	if rr := fx.api(keyC, "GET", "/api/tenant/servers", nil); rr.Code != http.StatusOK {
		t.Fatalf("inactive view = %d", rr.Code)
	} else if decode(t, rr)["entitled"] != false {
		t.Fatal("inactive tenant must report entitled=false")
	}
	if rr := fx.api(keyC, "POST", "/api/tenant/servers", map[string]any{"name": "new", "url": "https://" + fxUpstreamHost + "/mcp"}); rr.Code != http.StatusPaymentRequired {
		t.Fatalf("inactive add = %d", rr.Code)
	} else if decode(t, rr)["url"] == nil {
		t.Fatal("402 must carry the upgrade URL")
	}
	before := fx.up.count()
	if rr := fx.api(keyC, "POST", "/api/tenant/servers/"+id+"/test", nil); rr.Code != http.StatusPaymentRequired {
		t.Fatalf("inactive test = %d", rr.Code)
	}
	if fx.up.count() != before {
		t.Fatal("inactive test reached the upstream")
	}
	if rr := fx.api(keyC, "PATCH", "/api/tenant/servers/"+id, map[string]any{"name": "renamed"}); rr.Code != http.StatusPaymentRequired {
		t.Fatalf("inactive patch = %d", rr.Code)
	}
	if rr := fx.api(keyC, "PATCH", "/api/tenant/tools/"+uuidN(999), map[string]any{"enabled": false}); rr.Code != http.StatusPaymentRequired {
		t.Fatalf("inactive tool toggle = %d", rr.Code)
	}
	// Removing their own server stays allowed.
	if rr := fx.api(keyC, "DELETE", "/api/tenant/servers/"+id, nil); rr.Code != http.StatusOK {
		t.Fatalf("inactive delete = %d", rr.Code)
	}
}

func TestTenantTestIsRateLimitedPerTenant(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	fx.srv.tenantAPI.limiter = NewRateLimiter(0, 2)
	fx.public = fx.srv.TenantAPIHandler() // handlers copy the config: rebuild after the change
	id := decode(t, fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "fixture", "url": "https://" + fxUpstreamHost + "/mcp"}))["server"].(map[string]any)["id"].(string)
	codes := []int{}
	for i := 0; i < 3; i++ {
		codes = append(codes, fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil).Code)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != http.StatusTooManyRequests {
		t.Fatalf("test codes = %v, want 200 200 429", codes)
	}
	// B has its own bucket.
	idB := decode(t, fx.api(keyB, "POST", "/api/tenant/servers", map[string]any{
		"name": "fixture", "url": "https://" + fxUpstreamHost + "/mcp"}))["server"].(map[string]any)["id"].(string)
	if rr := fx.api(keyB, "POST", "/api/tenant/servers/"+idB+"/test", nil); rr.Code != 200 {
		t.Fatalf("B's first test = %d", rr.Code)
	}
}

func TestTenantFailedTestReportsErrorWithoutSecrets(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	// An upstream that is blocked by policy: the error is reported, not the value.
	rr := fx.api(keyA, "POST", "/api/tenant/servers", map[string]any{
		"name": "rebinder", "url": "https://" + fxUpstreamHost + "/mcp",
		"headers": map[string]string{"Authorization": "Bearer should-not-leak-1234"},
	})
	id := decode(t, rr)["server"].(map[string]any)["id"].(string)
	fx.db.servers[id].URL = strp("https://rebind.tenant-fixture.net/mcp") // DNS changed after create
	out := decode(t, fx.api(keyA, "POST", "/api/tenant/servers/"+id+"/test", nil))
	if out["ok"] != false || out["status"] != "error" {
		t.Fatalf("test = %v", out)
	}
	if strings.Contains(fmt.Sprint(out), "should-not-leak") {
		t.Fatal("error reply leaked a credential")
	}
	// The failure is recorded for the dashboard.
	list := decode(t, fx.api(keyA, "GET", "/api/tenant/servers", nil))["servers"].([]any)
	if s := list[0].(map[string]any); s["status"] != "error" || s["last_error"] == nil {
		t.Fatalf("server view after failure = %v", s)
	}
}

func TestTenantAPIDisabledWithoutServiceTokenStaysOff(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 5)
	fx.srv.tenantAPI.hasToken = false
	fx.internal = fx.srv.TenantAPIInternalHandler()
	if rr := fx.svc(userA, "GET", "/api/tenant/servers", nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("internal without a token = %d", rr.Code)
	}
	if err := (&Server{}).EnableTenantAPI(fx.db, TenantAPIConfig{}); err == nil {
		t.Fatal("tenant API must require tenant mode")
	}
	short := &Server{tenants: &tenantGate{}, agg: fx.srv.agg}
	if err := short.EnableTenantAPI(fx.db, TenantAPIConfig{ServiceToken: "too-short"}); err == nil {
		t.Fatal("a short service token must be refused")
	}
}

// The operator's non-admin key is bound to the operator user, which also owns
// the operator's legacy rows. Through the tenant API that key must see none of
// them, and must not be able to change, delete, test or convert them.
func TestTenantAPIIgnoresLegacyRowsEvenForTheOwnersKey(t *testing.T) {
	fx, _, _, _, _ := standardFixture(t, 2)
	opID := ""
	for _, id := range fx.db.order {
		if fx.db.servers[id].Name == "opsrv" {
			opID = id
		}
	}
	if opID == "" {
		t.Fatal("fixture lacks the operator row")
	}
	before := *fx.db.servers[opID]

	for _, s := range decode(t, fx.api(keyOpNon, "GET", "/api/tenant/servers", nil))["servers"].([]any) {
		if s.(map[string]any)["name"] == "opsrv" {
			t.Fatal("the owner's tenant key lists a legacy row")
		}
	}
	if rr := fx.api(keyOpNon, "PATCH", "/api/tenant/servers/"+opID, map[string]any{"url": "https://" + fxUpstreamHost + "/x"}); rr.Code != http.StatusNotFound {
		t.Fatalf("PATCH legacy row = %d, want 404", rr.Code)
	}
	if rr := fx.api(keyOpNon, "DELETE", "/api/tenant/servers/"+opID, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("DELETE legacy row = %d, want 404", rr.Code)
	}
	if rr := fx.api(keyOpNon, "POST", "/api/tenant/servers/"+opID+"/test", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("test legacy row = %d, want 404", rr.Code)
	}
	after := fx.db.servers[opID]
	if after.TenantManaged != before.TenantManaged || deref(after.URL) != deref(before.URL) || after.Name != before.Name {
		t.Fatalf("legacy row changed through the tenant API: %+v", after)
	}
	// A name clash with a legacy row is refused, as the unique index would.
	if rr := fx.api(keyOpNon, "POST", "/api/tenant/servers", map[string]any{"name": "opsrv", "url": "https://" + fxUpstreamHost + "/mcp"}); rr.Code != http.StatusConflict {
		t.Fatalf("name clash with a legacy row = %d, want 409", rr.Code)
	}
	// Legacy rows do not use up the owner's tenant quota (fixture limit: 2).
	if rr := fx.api(keyOpNon, "POST", "/api/tenant/servers", map[string]any{"name": "fresh", "url": "https://" + fxUpstreamHost + "/mcp"}); rr.Code != http.StatusCreated {
		t.Fatalf("legacy row counted against the quota: %d %s", rr.Code, rr.Body.String())
	}
}

// jsonEqual compares two JSON documents semantically (key order and spacing do
// not matter), as a jsonb comparison does. A missing document equals "{}".
func jsonEqual(a, b json.RawMessage) bool {
	norm := func(x json.RawMessage) any {
		if len(x) == 0 {
			x = json.RawMessage(`{}`)
		}
		var v any
		if err := json.Unmarshal(x, &v); err != nil {
			return string(x)
		}
		return v
	}
	return reflect.DeepEqual(norm(a), norm(b))
}
