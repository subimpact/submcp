package ui

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/subimpact/submcp/internal/db"
	"github.com/subimpact/submcp/internal/mcp"
)

//go:embed static
var staticFS embed.FS

// UI is the embedded web surface.
// Serves:
//   - GET  /            -> public landing page (features, live stats, support)
//   - GET  /admin/      -> admin SPA (login + dashboard)
//   - GET  /api/public/stats -> unauthenticated non-sensitive stats (landing page)
//   - POST /api/admin/login    -> {key} -> sets session cookie
//   - POST /api/admin/logout   -> clears session
//   - GET  /api/admin/overview -> servers, namespaces, endpoints, keys, tools
//   - CRUD /api/admin/servers|namespaces|endpoints|keys
//   - POST /api/admin/servers/:uuid/test -> live connectivity check
type UI struct {
	db       *db.Pool
	sessions *sessionStore
	start    time.Time

	// Public stats cache (A8): 60s TTL, avoids DB hits per landing page load.
	statsMu    sync.Mutex
	statsCache map[string]any
	statsAt    time.Time
}

// New creates the web UI handler.
func New(dbPool *db.Pool) *UI {
	return &UI{db: dbPool, sessions: newSessionStore(), start: time.Now()}
}

// SweepSessions removes expired admin sessions (P1-4).
func (u *UI) SweepSessions() {
	u.sessions.sweep()
}

// Handler returns the UI's http.Handler (mounted at /).
func (u *UI) Handler() http.Handler {
	mux := http.NewServeMux()

	// Public landing page.
	mux.HandleFunc("/", u.handleLanding)
	mux.HandleFunc("/api/public/stats", u.handlePublicStats)

	// Admin static assets (no auth — they contain no data).
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(sub))))

	// Admin API (auth required except login).
	mux.HandleFunc("/api/admin/login", u.handleLogin)
	mux.HandleFunc("/api/admin/logout", u.handleLogout)
	mux.HandleFunc("/api/admin/overview", u.requireAuth(u.handleOverview))
	mux.HandleFunc("/api/admin/servers", u.requireAuth(u.handleServers))
	mux.HandleFunc("/api/admin/servers/", u.requireAuth(u.handleServerItem))
	mux.HandleFunc("/api/admin/namespaces", u.requireAuth(u.handleNamespaces))
	mux.HandleFunc("/api/admin/namespaces/", u.requireAuth(u.handleNamespaceItem))
	mux.HandleFunc("/api/admin/endpoints", u.requireAuth(u.handleEndpoints))
	mux.HandleFunc("/api/admin/endpoints/", u.requireAuth(u.handleEndpointItem))
	mux.HandleFunc("/api/admin/keys", u.requireAuth(u.handleKeys))
	mux.HandleFunc("/api/admin/keys/", u.requireAuth(u.handleKeyItem))

	// Admin SPA.
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/" && r.URL.Path != "/admin" {
			http.NotFound(w, r)
			return
		}
		b, _ := staticFS.ReadFile("static/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})

	return mux
}

// handleLanding serves the public landing page.
func (u *UI) handleLanding(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	b, _ := staticFS.ReadFile("static/landing.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(b)
}

// handlePublicStats returns non-sensitive gateway stats for the landing page.
// No auth: exposes only names, types, error status, and counts.
// Cached in-process for 60s (A8) so page loads don't hit the DB on every
// request; errors are generic (no DB internals leaked to unauthenticated
// callers).
func (u *UI) handlePublicStats(w http.ResponseWriter, r *http.Request) {
	u.statsMu.Lock()
	if u.statsCache != nil && time.Since(u.statsAt) < 60*time.Second {
		writeJSON(w, http.StatusOK, u.statsCache)
		u.statsMu.Unlock()
		return
	}
	u.statsMu.Unlock()

	ctx := r.Context()
	servers, err := u.db.ListServers(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "unavailable"})
		return
	}
	toolCount, err := u.db.CountTools(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "unavailable"})
		return
	}
	nsCount, err := u.db.CountNamespaces(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "unavailable"})
		return
	}
	upstreams := make([]map[string]any, 0, len(servers))
	for _, s := range servers {
		upstreams = append(upstreams, map[string]any{
			"name":         s.Name,
			"type":         s.Type,
			"error_status": s.ErrorStatus,
		})
	}
	payload := map[string]any{
		"version":    "0.1.0",
		"uptime":     time.Since(u.start).Round(time.Second).String(),
		"servers":    len(servers),
		"namespaces": nsCount,
		"tools":      toolCount,
		"upstreams":  upstreams,
	}

	u.statsMu.Lock()
	u.statsCache = payload
	u.statsAt = time.Now()
	u.statsMu.Unlock()

	writeJSON(w, http.StatusOK, payload)
}

// --- sessions ---

type sessionStore struct {
	mu       sync.Mutex
	sessions map[string]session // token -> session
}

type session struct {
	keyName string
	expires time.Time
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[string]session)}
}

func (s *sessionStore) create(keyName string) string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	s.mu.Lock()
	s.sessions[token] = session{keyName: keyName, expires: time.Now().Add(24 * time.Hour)}
	s.mu.Unlock()
	return token
}

func (s *sessionStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[token]
	if !ok {
		return false
	}
	if time.Now().After(sess.expires) {
		delete(s.sessions, token)
		return false
	}
	return true
}

func (s *sessionStore) destroy(token string) {
	s.mu.Lock()
	delete(s.sessions, token)
	s.mu.Unlock()
}

// sweep removes expired admin sessions (P1-4: admin sessionStore sweep).
func (s *sessionStore) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for token, sess := range s.sessions {
		if now.After(sess.expires) {
			delete(s.sessions, token)
		}
	}
}

// --- auth helpers ---

const sessionCookie = "submcp_session"

func (u *UI) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil || !u.sessions.valid(c.Value) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (u *UI) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Key) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "key_required"})
		return
	}
	key, err := u.db.ValidateAPIKey(r.Context(), strings.TrimSpace(body.Key))
	if err != nil || key == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_key"})
		return
	}
	if !key.IsAdmin {
		// Gateway keys are NOT admin credentials. Reject non-admin keys
		// at the admin login (security fix: any API key no longer grants
		// full admin access).
		writeJSON(w, http.StatusForbidden, map[string]any{"error": "not_admin"})
		return
	}
	token := u.sessions.create(key.Name)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   86400,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "name": key.Name})
}

func (u *UI) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		u.sessions.destroy(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// maskServer strips the bearer token from a server before it leaves the
// admin API (security fix: no credential exfiltration via overview).
func maskServer(s db.MCPServer) db.MCPServer {
	s.BearerToken = nil
	return s
}

// maskKey strips the key value from an API key before it leaves the admin
// API. The full key is only returned once, at creation time.
func maskKey(k db.APIKey) db.APIKey {
	k.Key = ""
	return k
}

// --- overview ---

func (u *UI) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	servers, err := u.db.ListServers(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	namespaces, err := u.db.ListNamespaces(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	endpoints, err := u.db.ListEndpoints(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	keys, err := u.db.ListAPIKeys(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	toolCount, err := u.db.CountTools(ctx)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	// Namespace -> server mappings (for the matrix view).
	mappings := map[string][]db.NamespaceServerMapping{}
	for _, ns := range namespaces {
		ms, err := u.db.ListNamespaceServerMappings(ctx, ns.UUID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		mappings[ns.UUID] = ms
	}
	// Mask credentials before returning.
	maskedServers := make([]db.MCPServer, 0, len(servers))
	for _, s := range servers {
		maskedServers = append(maskedServers, maskServer(s))
	}
	maskedKeys := make([]db.APIKey, 0, len(keys))
	for _, k := range keys {
		maskedKeys = append(maskedKeys, maskKey(k))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":    maskedServers,
		"namespaces": namespaces,
		"endpoints":  endpoints,
		"keys":       maskedKeys,
		"mappings":   mappings,
		"tool_count": toolCount,
	})
}

// --- servers ---

func (u *UI) handleServers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		servers, err := u.db.ListServers(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		masked := make([]db.MCPServer, 0, len(servers))
		for _, s := range servers {
			masked = append(masked, maskServer(s))
		}
		writeJSON(w, http.StatusOK, map[string]any{"servers": masked})
	case http.MethodPost:
		var s db.MCPServer
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_body"})
			return
		}
		if strings.TrimSpace(s.Name) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name_required"})
			return
		}
		if s.Type == "" {
			s.Type = db.ServerTypeStreamableHTTP
		}
		if s.Args == nil {
			s.Args = []string{}
		}
		if s.Env == nil {
			s.Env = json.RawMessage(`{}`)
		}
		if s.Headers == nil {
			s.Headers = json.RawMessage(`{}`)
		}
		if err := u.db.CreateServer(r.Context(), &s); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"server": s})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func (u *UI) handleServerItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/servers/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id_required"})
		return
	}
	// Test-connection sub-route.
	if strings.HasSuffix(id, "/test") {
		u.handleServerTest(w, r, strings.TrimSuffix(id, "/test"))
		return
	}
	switch r.Method {
	case http.MethodPut:
		var s db.MCPServer
		if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_body"})
			return
		}
		s.UUID = id
		// Merge with the existing row so NOT NULL columns (args, env,
		// headers) never get NULLed when the SPA omits them (fix for
		// the broken Edit-server path).
		existing, err := u.db.GetServer(r.Context(), id)
		if err != nil || existing == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "server_not_found"})
			return
		}
		if s.Args == nil {
			s.Args = existing.Args
		}
		if s.Env == nil {
			s.Env = existing.Env
		}
		if s.Headers == nil {
			s.Headers = existing.Headers
		}
		if err := u.db.UpdateServer(r.Context(), &s); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodDelete:
		if err := u.db.DeleteServer(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

// handleServerTest performs a live initialize + tools/list against the
// upstream to verify connectivity (used by the UI "Test" button).
func (u *UI) handleServerTest(w http.ResponseWriter, r *http.Request, id string) {
	srv, err := u.db.GetServer(r.Context(), id)
	if err != nil || srv == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "server_not_found"})
		return
	}
	if srv.Type != db.ServerTypeStreamableHTTP || srv.URL == nil || *srv.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "only_streamable_http_supported"})
		return
	}
	headers := map[string]string{}
	if len(srv.Headers) > 0 {
		_ = json.Unmarshal(srv.Headers, &headers)
	}
	client := mcp.NewUpstreamClient(mcp.UpstreamConfig{
		Name:        srv.Name,
		URL:         *srv.URL,
		BearerToken: deref(srv.BearerToken),
		Headers:     headers,
		Timeout:     10 * time.Second,
	})
	ctx := r.Context()
	if err := client.Connect(ctx); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	defer client.Close(ctx)
	tools, err := client.ListTools(ctx)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tools": len(tools)})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// --- namespaces ---

func (u *UI) handleNamespaces(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		ns, err := u.db.ListNamespaces(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"namespaces": ns})
	case http.MethodPost:
		var n db.Namespace
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_body"})
			return
		}
		if strings.TrimSpace(n.Name) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name_required"})
			return
		}
		if err := u.db.CreateNamespace(r.Context(), &n); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"namespace": n})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func (u *UI) handleNamespaceItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/namespaces/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id_required"})
		return
	}
	switch r.Method {
	case http.MethodPost:
		// Toggle a server mapping: {server_uuid, status}
		var body struct {
			ServerUUID string `json:"server_uuid"`
			Status     string `json:"status"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ServerUUID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "server_uuid_required"})
			return
		}
		status := db.ServerStatusActive
		if body.Status == "INACTIVE" {
			status = db.ServerStatusInactive
		}
		if err := u.db.SetServerMapping(r.Context(), id, body.ServerUUID, status); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodDelete:
		if err := u.db.DeleteNamespace(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

// --- endpoints ---

func (u *UI) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		eps, err := u.db.ListEndpoints(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"endpoints": eps})
	case http.MethodPost:
		var e db.Endpoint
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_body"})
			return
		}
		if strings.TrimSpace(e.Name) == "" || e.NamespaceUUID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name_and_namespace_required"})
			return
		}
		if err := u.db.CreateEndpoint(r.Context(), &e); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"endpoint": e})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func (u *UI) handleEndpointItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/endpoints/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id_required"})
		return
	}
	switch r.Method {
	case http.MethodPut:
		var e db.Endpoint
		if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_body"})
			return
		}
		e.UUID = id
		if err := u.db.UpdateEndpoint(r.Context(), &e); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	case http.MethodDelete:
		if err := u.db.DeleteEndpoint(r.Context(), id); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

// --- API keys ---

func (u *UI) handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys, err := u.db.ListAPIKeys(r.Context())
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"keys": keys})
	case http.MethodPost:
		var body struct {
			Name  string `json:"name"`
			Key   string `json:"key"`
			Admin bool   `json:"admin"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "name_required"})
			return
		}
		key := strings.TrimSpace(body.Key)
		if key == "" {
			// Generate a key if none provided.
			b := make([]byte, 24)
			_, _ = rand.Read(b)
			key = "sk_mt_" + hex.EncodeToString(b)
		}
		k, err := u.db.CreateAPIKey(r.Context(), body.Name, key, body.Admin)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"key": k})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

func (u *UI) handleKeyItem(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/admin/keys/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "id_required"})
		return
	}
	switch r.Method {
	case http.MethodPost:
		var body struct {
			Active *bool `json:"active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Active == nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "active_required"})
			return
		}
		if err := u.db.SetAPIKeyActive(r.Context(), id, *body.Active); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": "method_not_allowed"})
	}
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
