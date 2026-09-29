package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/subimpact/submcp/internal/db"
)

// Fix 13: regression tests for the tenant-scoping fixes. These are the
// checks whose absence let the P0 IDOR/ownership holes ship. All hermetic
// (fake Store, no live Postgres).

// spyStore records what the handlers asked the DB to do and lets tests
// decide what "exists for this user" means.
type spyStore struct {
	ownedNamespaces map[string]*string // namespace uuid -> owner userID (nil = root)
	ownedServers    map[string]*string // server uuid -> owner userID
	listCalls       [][]*string
	deleteCalls     []struct{ uuid string; userID *string }
	updateCalls     []struct {
		uuid   string
		userID *string
	}
	setKeyCalls []struct {
		uuid   string
		userID *string
	}
	mapped     bool
	mapCalls   int
	createKey  *struct{ admin bool; userID *string }
	createEpNS *string // namespace uuid used in CreateEndpoint
}

func (s *spyStore) CountNamespaces(context.Context) (int, error)      { return 0, nil }
func (s *spyStore) CountTools(context.Context) (int, error)           { return 0, nil }
func (s *spyStore) CreateAPIKey(_ context.Context, _ string, _ string, isAdmin bool, userID *string) (*db.APIKey, error) {
	if s.createKey == nil {
		s.createKey = &struct {
			admin  bool
			userID *string
		}{}
	}
	s.createKey.admin = isAdmin
	s.createKey.userID = userID
	return &db.APIKey{UUID: "k1", IsActive: true, IsAdmin: isAdmin}, nil
}
func (s *spyStore) CreateEndpoint(_ context.Context, e *db.Endpoint) error {
	s.createEpNS = &e.NamespaceUUID
	return nil
}
func (s *spyStore) CreateNamespace(context.Context, *db.Namespace) error { return nil }
func (s *spyStore) CreateServer(context.Context, *db.MCPServer) error   { return nil }
func (s *spyStore) DeleteEndpoint(_ context.Context, uuid string, userID *string) error {
	s.deleteCalls = append(s.deleteCalls, struct {
		uuid   string
		userID *string
	}{uuid, userID})
	return nil
}
func (s *spyStore) DeleteNamespace(_ context.Context, uuid string, userID *string) error {
	s.deleteCalls = append(s.deleteCalls, struct {
		uuid   string
		userID *string
	}{uuid, userID})
	return nil
}
func (s *spyStore) DeleteServer(_ context.Context, uuid string, userID *string) error {
	s.deleteCalls = append(s.deleteCalls, struct {
		uuid   string
		userID *string
	}{uuid, userID})
	return nil
}
func (s *spyStore) GetNamespace(_ context.Context, uuid string, userID *string) (*db.Namespace, error) {
	owner, ok := s.ownedNamespaces[uuid]
	if !ok {
		return nil, nil
	}
	if userID != nil && owner != nil && *owner != *userID {
		return nil, nil // not this user's namespace
	}
	return &db.Namespace{UUID: uuid, UserID: owner}, nil
}
func (s *spyStore) GetServer(_ context.Context, uuid string, userID *string) (*db.MCPServer, error) {
	owner, ok := s.ownedServers[uuid]
	if !ok {
		return nil, nil
	}
	if userID != nil && owner != nil && *owner != *userID {
		return nil, nil
	}
	return &db.MCPServer{UUID: uuid, UserID: owner}, nil
}
func (s *spyStore) ListAPIKeys(context.Context, *string) ([]db.APIKey, error)  { return nil, nil }
func (s *spyStore) ListEndpoints(_ context.Context, userID *string) ([]db.Endpoint, error) {
	s.listCalls = append(s.listCalls, []*string{userID})
	return nil, nil
}
func (s *spyStore) ListNamespaceServerMappings(context.Context, string) ([]db.NamespaceServerMapping, error) {
	return nil, nil
}
func (s *spyStore) ListNamespaces(context.Context, *string) ([]db.Namespace, error) {
	return nil, nil
}
func (s *spyStore) ListServers(context.Context, *string) ([]db.MCPServer, error) { return nil, nil }
func (s *spyStore) SetAPIKeyActive(_ context.Context, uuid string, _ bool, userID *string) error {
	s.setKeyCalls = append(s.setKeyCalls, struct {
		uuid   string
		userID *string
	}{uuid, userID})
	return nil
}
func (s *spyStore) SetServerMapping(context.Context, string, string, db.ServerStatus) error {
	s.mapped = true
	s.mapCalls++
	return nil
}
func (s *spyStore) UpdateEndpoint(_ context.Context, e *db.Endpoint, userID *string) error {
	s.updateCalls = append(s.updateCalls, struct {
		uuid   string
		userID *string
	}{e.UUID, userID})
	return nil
}
func (s *spyStore) UpdateServer(context.Context, *db.MCPServer, *string) error  { return nil }
func (s *spyStore) ValidateAPIKey(context.Context, string) (*db.APIKey, error)   { return nil, nil }

// sessAuth authenticates a request through the REAL session store
// (requireAuth runs first and rejects cookie-less requests with 401).
func sessAuth(u *UI, r *http.Request, userID *string) *http.Request {
	tok := u.sessions.create("test-key", userID)
	r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
	return r
}

func strp(s string) *string { return &s }

// Fix 1: mapping a server owned by another user must be rejected.
func TestMappingRejectsForeignServer(t *testing.T) {
	s := &spyStore{
		ownedNamespaces: map[string]*string{"ns1": strp("user-a")},
		ownedServers:    map[string]*string{"srv1": strp("user-b")}, // foreign!
	}
	u := New(s)
	req := sessAuth(u, httptest.NewRequest(http.MethodPost, "/api/admin/namespaces/ns1",
		strings.NewReader(`{"server_uuid":"srv1","status":"ACTIVE"}`)), strp("user-a"))
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (foreign server must not map)", rr.Code)
	}
	if s.mapped {
		t.Fatalf("SetServerMapping MUST NOT be called for a foreign server")
	}
}

// Fix 1: mapping my own server to my own namespace works.
func TestMappingAllowsOwnServer(t *testing.T) {
	s := &spyStore{
		ownedNamespaces: map[string]*string{"ns1": strp("user-a")},
		ownedServers:    map[string]*string{"srv1": strp("user-a")},
	}
	u := New(s)
	req := sessAuth(u, httptest.NewRequest(http.MethodPost, "/api/admin/namespaces/ns1",
		strings.NewReader(`{"server_uuid":"srv1","status":"ACTIVE"}`)), strp("user-a"))
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if !s.mapped {
		t.Fatalf("SetServerMapping should have been called")
	}
}

// Fix 2: deletes must pass the session userID into the query.
func TestDeletesPassSessionUserID(t *testing.T) {
	s := &spyStore{}
	u := New(s)
	for _, path := range []string{
		"/api/admin/servers/srv1",
		"/api/admin/namespaces/ns1",
		"/api/admin/endpoints/ep1",
	} {
		req := sessAuth(u, httptest.NewRequest(http.MethodDelete, path, nil), strp("user-a"))
		rr := httptest.NewRecorder()
		u.Handler().ServeHTTP(rr, req)
	}
	if len(s.deleteCalls) != 3 {
		t.Fatalf("expected 3 delete calls, got %d", len(s.deleteCalls))
	}
	for _, c := range s.deleteCalls {
		if c.userID == nil || *c.userID != "user-a" {
			t.Fatalf("delete %s did not scope by session userID: %+v", c.uuid, c.userID)
		}
	}
}

// Fix 2: creating an endpoint against a foreign namespace must 400.
func TestCreateEndpointRejectsForeignNamespace(t *testing.T) {
	s := &spyStore{ownedNamespaces: map[string]*string{"ns1": strp("user-b")}}
	u := New(s)
	req := sessAuth(u, httptest.NewRequest(http.MethodPost, "/api/admin/endpoints",
		strings.NewReader(`{"name":"all","namespace_uuid":"ns1"}`)), strp("user-a"))
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (foreign namespace)", rr.Code)
	}
	if s.createEpNS != nil {
		t.Fatalf("CreateEndpoint MUST NOT run against a foreign namespace")
	}
}

// Fix 3: ListEndpoints must be scoped by the session userID.
func TestListEndpointsScoped(t *testing.T) {
	s := &spyStore{}
	u := New(s)
	req := sessAuth(u, httptest.NewRequest(http.MethodGet, "/api/admin/endpoints", nil), strp("user-a"))
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if len(s.listCalls) != 1 {
		t.Fatalf("expected 1 list call, got %d", len(s.listCalls))
	}
	got := s.listCalls[0][0]
	if got == nil || *got != "user-a" {
		t.Fatalf("ListEndpoints not scoped to session user: %+v", got)
	}
}

// Fix 4: tenant sessions cannot mint admin keys.
func TestTenantCannotMintAdminKey(t *testing.T) {
	s := &spyStore{}
	u := New(s)
	req := sessAuth(u, httptest.NewRequest(http.MethodPost, "/api/admin/keys",
		strings.NewReader(`{"name":"evil","admin":true}`)), strp("user-a"))
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if s.createKey == nil {
		t.Fatalf("CreateAPIKey not called")
	}
	if s.createKey.admin {
		t.Fatalf("tenant session minted an ADMIN key (privilege escalation)")
	}
}

// Fix 4: the root operator session (nil userID) may mint admin keys.
func TestOperatorCanMintAdminKey(t *testing.T) {
	s := &spyStore{}
	u := New(s)
	req := sessAuth(u, httptest.NewRequest(http.MethodPost, "/api/admin/keys",
		strings.NewReader(`{"name":"root","admin":true}`)), nil)
	rr := httptest.NewRecorder()
	u.Handler().ServeHTTP(rr, req)
	if s.createKey == nil || !s.createKey.admin {
		t.Fatalf("operator session should be able to mint admin keys")
	}
}

var _ = json.Marshal
