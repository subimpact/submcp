package mcp

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// Tenant API (SaaS phase 4): tenants manage their own upstream MCP servers.
//
// Two listeners serve the same routes with different authentication:
//
//   - Public (Traefik-routed, /api/tenant/ on the gateway hosts): X-API-Key
//     only. The key must be a non-admin key bound to a tenant. Service headers
//     are ignored here.
//   - Internal (TENANT_API_INTERNAL_ADDR, default :12013): service auth only,
//     X-Submcp-Service-Token plus X-Submcp-Tenant-User. The SaaS dashboard calls
//     it over the docker network, through the submcp-gateway alias. The port is
//     never published and Traefik has no route to it.
//
// Every query is scoped to the caller's user_id. Entitlement is enforced on
// writes: an inactive tenant can read but not add, change or test servers.
// Removing a server stays allowed.

const (
	tenantServiceTokenHeader = "X-Submcp-Service-Token"
	tenantUserHeader         = "X-Submcp-Tenant-User"
	tenantMaxBodyBytes       = 16 << 10
	tenantMaxHeaders         = 10
	tenantMaxHeaderValueLen  = 4096
	tenantMaxHeadersTotal    = 8192
	tenantServiceTokenMinLen = 32
	tenantDefaultMaxServers  = 10
	tenantDefaultTestPerMin  = 10
	tenantDashboardURL       = "https://mcp.subimpact.net/dashboard"
)

// TenantServerStore is the DB surface of the tenant API (*db.Pool implements it).
type TenantServerStore interface {
	GetTenantByUserID(ctx context.Context, userID string) (*db.Tenant, error)
	TenantNamespaceUUID(ctx context.Context, userID string) (string, error)
	ListTenantServers(ctx context.Context, userID string) ([]db.TenantServerRow, error)
	CreateTenantServer(ctx context.Context, userID, nsUUID string, s *db.MCPServer, maxServers int) error
	UpdateTenantServer(ctx context.Context, userID string, s *db.MCPServer) (bool, error)
	DeleteTenantServer(ctx context.Context, userID, serverUUID string) (bool, error)
	ListTenantTools(ctx context.Context, userID, nsUUID string) ([]db.TenantToolRow, error)
	GetTenantTool(ctx context.Context, userID, toolUUID, nsUUID string) (*db.TenantToolRow, error)
	SetToolMappingStatus(ctx context.Context, nsUUID, toolUUID, serverUUID string, status db.ServerStatus) error
}

// TenantAPIConfig sizes the tenant API. ServiceToken enables the internal
// listener (empty leaves it off; the public API still works).
type TenantAPIConfig struct {
	ServiceToken  string
	MaxServers    int // per tenant; default 10
	TestPerMinute int // test/refresh calls per tenant per minute; default 10
}

// tenantAPI is one configured instance. The public and internal handlers are
// copies that differ only in the internal flag; they share the rate limiter.
type tenantAPI struct {
	srv        *Server
	store      TenantServerStore
	keys       KeyValidator
	box        *SecretBox
	policy     *TenantNetPolicy
	maxServers int
	limiter    *RateLimiter // test/refresh, per tenant
	tokenSum   [sha256.Size]byte
	hasToken   bool
	internal   bool
}

// EnableTenantAPI turns on the tenant API. It requires tenant mode
// (EnableTenants) and the tenant upstream wiring (SetTenantUpstreams) so the
// credential box and network policy are the same objects the aggregator uses.
func (s *Server) EnableTenantAPI(store TenantServerStore, cfg TenantAPIConfig) error {
	if s.tenants == nil {
		return errors.New("tenant API requires tenant mode (TENANT_BASE_HOST)")
	}
	if s.agg == nil || s.agg.tenantPolicy == nil {
		return errors.New("tenant API requires Aggregator.SetTenantUpstreams")
	}
	if cfg.MaxServers <= 0 {
		cfg.MaxServers = tenantDefaultMaxServers
	}
	if cfg.TestPerMinute <= 0 {
		cfg.TestPerMinute = tenantDefaultTestPerMin
	}
	t := &tenantAPI{
		srv:        s,
		store:      store,
		box:        s.agg.tenantBox,
		policy:     s.agg.tenantPolicy,
		maxServers: cfg.MaxServers,
		limiter:    NewRateLimiter(float64(cfg.TestPerMinute)/60, float64(cfg.TestPerMinute)),
	}
	if s.auth != nil {
		t.keys = s.auth.db
	}
	if cfg.ServiceToken != "" {
		if len(cfg.ServiceToken) < tenantServiceTokenMinLen {
			return fmt.Errorf("TENANT_API_SERVICE_TOKEN must be at least %d characters", tenantServiceTokenMinLen)
		}
		t.tokenSum = sha256.Sum256([]byte(cfg.ServiceToken))
		t.hasToken = true
	}
	s.tenantAPI = t
	return nil
}

// TenantAPIHandler serves the public tenant API (mounted at /api/tenant/ on the
// gateway hosts). Per-IP rate limiting applies as on the other gateway routes.
func (s *Server) TenantAPIHandler() http.Handler {
	if s.tenantAPI == nil {
		return tenantAPIDisabled()
	}
	h := *s.tenantAPI
	h.internal = false
	return s.limiter.Middleware(h.handler())
}

// TenantAPIInternalHandler serves the service-auth tenant API for the internal
// listener. Without a configured service token it refuses everything.
func (s *Server) TenantAPIInternalHandler() http.Handler {
	if s.tenantAPI == nil {
		return tenantAPIDisabled()
	}
	h := *s.tenantAPI
	h.internal = true
	return h.handler()
}

// TenantAPIEnabled reports whether EnableTenantAPI succeeded.
func (s *Server) TenantAPIEnabled() bool { return s.tenantAPI != nil }

func tenantAPIDisabled() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSONError(w, http.StatusNotFound, "not_found", "The tenant API is not enabled on this gateway.")
	})
}

type tenantCallerKey struct{}

// tenantCaller is the authenticated owner of a request.
type tenantCaller struct {
	UserID string
	Tenant *db.Tenant
}

func (t *tenantAPI) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tenant/servers", t.listServers)
	mux.HandleFunc("POST /api/tenant/servers", t.createServer)
	mux.HandleFunc("GET /api/tenant/servers/{id}", t.getServer)
	mux.HandleFunc("PATCH /api/tenant/servers/{id}", t.updateServer)
	mux.HandleFunc("DELETE /api/tenant/servers/{id}", t.deleteServer)
	mux.HandleFunc("POST /api/tenant/servers/{id}/test", t.testServer)
	mux.HandleFunc("POST /api/tenant/servers/{id}/refresh", t.testServer)
	mux.HandleFunc("GET /api/tenant/tools", t.listTools)
	mux.HandleFunc("PATCH /api/tenant/tools/{id}", t.setToolEnabled)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := t.authenticate(w, r)
		if !ok {
			return
		}
		mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tenantCallerKey{}, c)))
	})
}

// authenticate resolves the owner of a request. On failure it writes the
// response and returns false.
func (t *tenantAPI) authenticate(w http.ResponseWriter, r *http.Request) (*tenantCaller, bool) {
	ctx := r.Context()
	var uid string
	if t.internal {
		tok := r.Header.Get(tenantServiceTokenHeader)
		sum := sha256.Sum256([]byte(tok))
		if !t.hasToken || tok == "" || subtle.ConstantTimeCompare(sum[:], t.tokenSum[:]) != 1 {
			writeJSONError(w, http.StatusUnauthorized, "service_auth_failed", "Service authentication failed.")
			return nil, false
		}
		uid = r.Header.Get(tenantUserHeader)
		if !validUserID(uid) {
			writeJSONError(w, http.StatusBadRequest, "tenant_user_required", "The tenant user header is missing or invalid.")
			return nil, false
		}
	} else {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			writeJSONError(w, http.StatusUnauthorized, "authentication_required", "Authentication required via the X-API-Key header.")
			return nil, false
		}
		if t.keys == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "API key validation is not configured.")
			return nil, false
		}
		apiKey, err := t.keys.ValidateAPIKey(ctx, key)
		if err != nil || apiKey == nil {
			writeJSONError(w, http.StatusUnauthorized, "invalid_api_key", "The provided API key is invalid or expired.")
			return nil, false
		}
		if apiKey.IsAdmin {
			writeJSONError(w, http.StatusForbidden, "key_not_allowed", "Admin keys cannot use the tenant API. Use a tenant key from your dashboard.")
			return nil, false
		}
		if apiKey.UserID == nil {
			writeJSONError(w, http.StatusForbidden, "key_not_allowed", "This key is not bound to a tenant.")
			return nil, false
		}
		uid = *apiKey.UserID
	}
	tenant, err := t.store.GetTenantByUserID(ctx, uid)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return nil, false
	}
	if tenant == nil {
		writeJSONError(w, http.StatusForbidden, "no_tenant", "This account has no gateway.")
		return nil, false
	}
	return &tenantCaller{UserID: uid, Tenant: tenant}, true
}

func callerFrom(r *http.Request) *tenantCaller {
	c, _ := r.Context().Value(tenantCallerKey{}).(*tenantCaller)
	return c
}

// --- views ---

// tenantServerView is the wire shape of one server. Header values are masked;
// the URL is shown as stored (credentials are refused in URLs).
type tenantServerView struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	URL           string            `json:"url"`
	Type          string            `json:"type"`
	Headers       map[string]string `json:"headers"`
	Status        string            `json:"status"`
	ToolCount     int               `json:"tool_count"`
	LastError     *string           `json:"last_error"`
	LastCheckedAt *time.Time        `json:"last_checked_at"`
	CreatedAt     time.Time         `json:"created_at"`
}

func (t *tenantAPI) view(s db.MCPServer, toolCount int) tenantServerView {
	v := tenantServerView{
		ID:            s.UUID,
		Name:          s.Name,
		URL:           deref(s.URL),
		Type:          string(s.Type),
		Headers:       MaskHeaders(s.Headers, t.box),
		ToolCount:     toolCount,
		LastError:     s.LastError,
		LastCheckedAt: s.LastCheckedAt,
		CreatedAt:     s.CreatedAt,
	}
	switch {
	case s.ErrorStatus == db.ErrorStatusErr:
		v.Status = "error"
	case s.LastCheckedAt == nil:
		v.Status = "untested"
	case s.LastError != nil:
		v.Status = "error"
	default:
		v.Status = "ok"
	}
	return v
}

// --- servers ---

func (t *tenantAPI) listServers(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	rows, err := t.store.ListTenantServers(r.Context(), c.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	servers := make([]tenantServerView, 0, len(rows))
	for _, row := range rows {
		servers = append(servers, t.view(row.Server, row.ToolCount))
	}
	e := db.EvaluateEntitlement(c.Tenant, time.Now())
	writeTenantJSON(w, http.StatusOK, map[string]any{
		"servers":            servers,
		"limit":              t.maxServers,
		"entitled":           !e.Denied,
		"entitlement_reason": e.Reason,
		"endpoint_url":       t.endpointURL(c.Tenant.Slug),
		"upgrade_url":        tenantDashboardURL,
	})
}

func (t *tenantAPI) endpointURL(slug string) string {
	return fmt.Sprintf("https://%s.%s/metamcp/all/mcp", slug, t.srv.tenants.baseHost)
}

type tenantServerInput struct {
	Name    string            `json:"name"`
	URL     string            `json:"url"`
	Type    string            `json:"type"`
	Headers map[string]string `json:"headers"`
}

func (t *tenantAPI) createServer(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	if !t.srv.tenants.checkEntitlement(w, r, c.Tenant) {
		return
	}
	var in tenantServerInput
	if !decodeTenantJSON(w, r, &in) {
		return
	}
	name, ok := validTenantName(w, in.Name)
	if !ok {
		return
	}
	typ, err := validTenantType(in.Type)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_type", err.Error())
		return
	}
	rawURL := strings.TrimSpace(in.URL)
	if !t.checkURL(w, r, rawURL) {
		return
	}
	headers, err := validTenantHeaders(in.Headers)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_headers", err.Error())
		return
	}
	for _, v := range headers {
		if IsMaskedValue(v) {
			writeJSONError(w, http.StatusBadRequest, "invalid_headers", "Enter the full credential value, not a masked one.")
			return
		}
	}
	nsUUID, err := t.store.TenantNamespaceUUID(r.Context(), c.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	if nsUUID == "" {
		writeJSONError(w, http.StatusConflict, "tenant_not_provisioned", "This account has no endpoint yet. Contact support.")
		return
	}
	sealed, err := t.sealHeaders(headers)
	if err != nil {
		writeJSONError(w, http.StatusServiceUnavailable, "credentials_unavailable", "Credential storage is not configured on this gateway.")
		return
	}

	srv := db.MCPServer{Name: name, Type: typ, URL: &rawURL, Headers: sealed}
	err = t.store.CreateTenantServer(r.Context(), c.UserID, nsUUID, &srv, t.maxServers)
	switch {
	case errors.Is(err, db.ErrTenantServerLimit):
		writeJSONError(w, http.StatusConflict, "server_limit_reached",
			fmt.Sprintf("You can have at most %d servers. Remove one to add another.", t.maxServers))
		return
	case errors.Is(err, db.ErrTenantNameTaken):
		writeJSONError(w, http.StatusConflict, "name_taken", "You already have a server with this name.")
		return
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	t.srv.agg.InvalidateNamespace(nsUUID)
	writeTenantJSON(w, http.StatusCreated, map[string]any{"server": t.view(srv, 0)})
}

// findServer returns the caller's server with the given id, or writes 404.
// Another tenant's id, an operator id and an unknown id all look the same.
func (t *tenantAPI) findServer(w http.ResponseWriter, r *http.Request, c *tenantCaller) (*db.TenantServerRow, bool) {
	id := r.PathValue("id")
	if !validUUIDString(id) {
		writeJSONError(w, http.StatusNotFound, "server_not_found", "No such server.")
		return nil, false
	}
	rows, err := t.store.ListTenantServers(r.Context(), c.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return nil, false
	}
	for i := range rows {
		if rows[i].Server.UUID == id {
			return &rows[i], true
		}
	}
	writeJSONError(w, http.StatusNotFound, "server_not_found", "No such server.")
	return nil, false
}

func (t *tenantAPI) getServer(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	row, ok := t.findServer(w, r, c)
	if !ok {
		return
	}
	writeTenantJSON(w, http.StatusOK, map[string]any{"server": t.view(row.Server, row.ToolCount)})
}

// tenantServerPatch is a partial update. A nil field is left unchanged.
type tenantServerPatch struct {
	Name    *string            `json:"name"`
	URL     *string            `json:"url"`
	Type    *string            `json:"type"`
	Headers *map[string]string `json:"headers"`
}

func (t *tenantAPI) updateServer(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	if !t.srv.tenants.checkEntitlement(w, r, c.Tenant) {
		return
	}
	row, ok := t.findServer(w, r, c)
	if !ok {
		return
	}
	var in tenantServerPatch
	if !decodeTenantJSON(w, r, &in) {
		return
	}
	cur := row.Server
	next := cur

	if in.Name != nil {
		name, ok := validTenantName(w, *in.Name)
		if !ok {
			return
		}
		next.Name = name
	}
	if in.Type != nil {
		typ, err := validTenantType(*in.Type)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_type", err.Error())
			return
		}
		next.Type = typ
	}
	if in.URL != nil {
		rawURL := strings.TrimSpace(*in.URL)
		if rawURL != deref(cur.URL) && !t.checkURL(w, r, rawURL) {
			return
		}
		next.URL = &rawURL
	}
	if in.Headers != nil {
		plain, err := validTenantHeaders(*in.Headers)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_headers", err.Error())
			return
		}
		merged, err := t.mergeHeaders(plain, cur.Headers)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_headers", err.Error())
			return
		}
		sealed, err := t.sealHeaders(merged)
		if err != nil {
			writeJSONError(w, http.StatusServiceUnavailable, "credentials_unavailable", "Credential storage is not configured on this gateway.")
			return
		}
		next.Headers = sealed
	}

	updated, err := t.store.UpdateTenantServer(r.Context(), c.UserID, &next)
	switch {
	case errors.Is(err, db.ErrTenantNameTaken):
		writeJSONError(w, http.StatusConflict, "name_taken", "You already have a server with this name.")
		return
	case err != nil:
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	case !updated:
		writeJSONError(w, http.StatusNotFound, "server_not_found", "No such server.")
		return
	}
	t.srv.agg.ForgetServer(cur.UUID)
	if ns, err := t.store.TenantNamespaceUUID(r.Context(), c.UserID); err == nil && ns != "" {
		t.srv.agg.InvalidateNamespace(ns)
	}
	next.TenantManaged = true
	next.ErrorStatus = db.ErrorStatusNone
	next.LastError = nil
	next.LastCheckedAt = nil
	writeTenantJSON(w, http.StatusOK, map[string]any{"server": t.view(next, row.ToolCount)})
}

func (t *tenantAPI) deleteServer(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	row, ok := t.findServer(w, r, c)
	if !ok {
		return
	}
	// Deletion stays open to inactive tenants: it only removes their own data.
	deleted, err := t.store.DeleteTenantServer(r.Context(), c.UserID, row.Server.UUID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	if !deleted {
		writeJSONError(w, http.StatusNotFound, "server_not_found", "No such server.")
		return
	}
	t.srv.agg.ForgetServer(row.Server.UUID)
	if ns, err := t.store.TenantNamespaceUUID(r.Context(), c.UserID); err == nil && ns != "" {
		t.srv.agg.InvalidateNamespace(ns)
	}
	writeTenantJSON(w, http.StatusOK, map[string]any{"ok": true, "id": row.Server.UUID})
}

// testServer connects to the upstream, lists its tools, stores them and records
// the outcome. Both /test and /refresh run this. Upstream failures are reported
// in the body (HTTP 200, ok=false), not as HTTP errors.
func (t *tenantAPI) testServer(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	if !t.srv.tenants.checkEntitlement(w, r, c.Tenant) {
		return
	}
	if !t.limiter.Allow(c.UserID) {
		w.Header().Set("Retry-After", "6")
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "Too many tests. Wait a few seconds and try again.")
		return
	}
	row, ok := t.findServer(w, r, c)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), tenantUpstreamTimeout+5*time.Second)
	defer cancel()
	n, err := t.srv.agg.RefreshServer(ctx, row.Server)
	if err != nil {
		writeTenantJSON(w, http.StatusOK, map[string]any{
			"ok":     false,
			"status": "error",
			"error":  err.Error(),
		})
		return
	}
	writeTenantJSON(w, http.StatusOK, map[string]any{
		"ok":         true,
		"status":     "ok",
		"tool_count": n,
	})
}

// --- tools ---

type tenantToolView struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"` // as clients see it: server__tool
	Description *string `json:"description"`
	ServerID    string  `json:"server_id"`
	Server      string  `json:"server"`
	Enabled     bool    `json:"enabled"`
}

func (t *tenantAPI) listTools(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	ns, err := t.store.TenantNamespaceUUID(r.Context(), c.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	rows, err := t.store.ListTenantTools(r.Context(), c.UserID, ns)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	out := make([]tenantToolView, 0, len(rows))
	for _, row := range rows {
		out = append(out, tenantToolView{
			ID:          row.ToolUUID,
			Name:        ToolName(row.ServerName, row.ToolName),
			Description: row.Description,
			ServerID:    row.ServerUUID,
			Server:      row.ServerName,
			Enabled:     row.Status == db.ServerStatusActive,
		})
	}
	writeTenantJSON(w, http.StatusOK, map[string]any{"tools": out})
}

func (t *tenantAPI) setToolEnabled(w http.ResponseWriter, r *http.Request) {
	c := callerFrom(r)
	if !t.srv.tenants.checkEntitlement(w, r, c.Tenant) {
		return
	}
	id := r.PathValue("id")
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if !decodeTenantJSON(w, r, &in) {
		return
	}
	if in.Enabled == nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "enabled (true or false) is required.")
		return
	}
	if !validUUIDString(id) {
		writeJSONError(w, http.StatusNotFound, "tool_not_found", "No such tool.")
		return
	}
	ns, err := t.store.TenantNamespaceUUID(r.Context(), c.UserID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	if ns == "" {
		writeJSONError(w, http.StatusConflict, "tenant_not_provisioned", "This account has no endpoint yet. Contact support.")
		return
	}
	tool, err := t.store.GetTenantTool(r.Context(), c.UserID, id, ns)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	if tool == nil {
		writeJSONError(w, http.StatusNotFound, "tool_not_found", "No such tool.")
		return
	}
	status := db.ServerStatusInactive
	if *in.Enabled {
		status = db.ServerStatusActive
	}
	if err := t.store.SetToolMappingStatus(r.Context(), ns, tool.ToolUUID, tool.ServerUUID, status); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	writeTenantJSON(w, http.StatusOK, map[string]any{
		"tool": tenantToolView{
			ID:          tool.ToolUUID,
			Name:        ToolName(tool.ServerName, tool.ToolName),
			Description: tool.Description,
			ServerID:    tool.ServerUUID,
			Server:      tool.ServerName,
			Enabled:     *in.Enabled,
		},
	})
}

// --- validation ---

var (
	tenantNameRe       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,39}$`)
	tenantHeaderNameRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	uuidRe             = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	userIDRe           = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
)

// tenantForbiddenHeaders are set by the transport or by the gateway itself.
var tenantForbiddenHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"upgrade": true, "te": true, "trailer": true, "keep-alive": true,
	"proxy-authorization": true, "proxy-connection": true, "mcp-session-id": true,
	"content-type": true, "accept": true, "expect": true,
}

func validUUIDString(s string) bool { return uuidRe.MatchString(s) }
func validUserID(s string) bool     { return userIDRe.MatchString(s) }

func validTenantName(w http.ResponseWriter, name string) (string, bool) {
	name = strings.TrimSpace(name)
	if !tenantNameRe.MatchString(name) {
		writeJSONError(w, http.StatusBadRequest, "invalid_name",
			"Name must be 1 to 40 letters, digits or dashes, starting with a letter or digit.")
		return "", false
	}
	return name, true
}

// validTenantType accepts exactly the two remote transports. STDIO would run a
// command on the gateway host and is never available to tenants.
func validTenantType(s string) (db.ServerType, error) {
	switch s {
	case "", string(db.ServerTypeStreamableHTTP):
		return db.ServerTypeStreamableHTTP, nil
	case string(db.ServerTypeSSE):
		return db.ServerTypeSSE, nil
	case string(db.ServerTypeStdio):
		return "", errors.New("STDIO servers are not available to tenants")
	}
	return "", errors.New("type must be exactly STREAMABLE_HTTP or SSE")
}

// validTenantHeaders checks a header map and returns it with canonical names.
func validTenantHeaders(in map[string]string) (map[string]string, error) {
	if len(in) > tenantMaxHeaders {
		return nil, fmt.Errorf("at most %d headers are allowed", tenantMaxHeaders)
	}
	out := make(map[string]string, len(in))
	total := 0
	for k, v := range in {
		name := http.CanonicalHeaderKey(strings.TrimSpace(k))
		if !tenantHeaderNameRe.MatchString(name) {
			return nil, errors.New("header names may use letters, digits and dashes only")
		}
		if tenantForbiddenHeaders[strings.ToLower(name)] {
			return nil, fmt.Errorf("the %s header cannot be set", name)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("header %s is given more than once", name)
		}
		if v == "" {
			return nil, fmt.Errorf("header %s has no value", name)
		}
		if len(v) > tenantMaxHeaderValueLen {
			return nil, fmt.Errorf("header %s is longer than %d bytes", name, tenantMaxHeaderValueLen)
		}
		if hasControlChars(v) {
			return nil, fmt.Errorf("header %s contains control characters", name)
		}
		out[name] = v
		total += len(name) + len(v)
	}
	if total > tenantMaxHeadersTotal {
		return nil, fmt.Errorf("headers are larger than %d bytes in total", tenantMaxHeadersTotal)
	}
	return out, nil
}

func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// checkURL validates a tenant URL and resolves its host through the policy.
// It performs DNS only; no connection to the target is opened.
func (t *tenantAPI) checkURL(w http.ResponseWriter, r *http.Request, raw string) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := CheckTenantTarget(ctx, raw, t.policy); err != nil {
		writeJSONError(w, http.StatusBadRequest, "url_not_allowed", err.Error())
		return false
	}
	return true
}

// sealHeaders encrypts a header map for storage. An empty map is stored as {}
// and needs no key.
func (t *tenantAPI) sealHeaders(plain map[string]string) (json.RawMessage, error) {
	if len(plain) == 0 {
		return json.RawMessage(`{}`), nil
	}
	return SealHeaders(plain, t.box)
}

// mergeHeaders resolves a submitted header map against the stored one: a masked
// placeholder keeps the stored credential, anything else is taken as typed.
func (t *tenantAPI) mergeHeaders(submitted map[string]string, stored json.RawMessage) (map[string]string, error) {
	current, err := OpenSealedHeaders(stored, t.box)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(submitted))
	for k, v := range submitted {
		if !IsMaskedValue(v) {
			out[k] = v
			continue
		}
		old, ok := current[k]
		if !ok || MaskSecret(old) != v {
			return nil, errors.New("a masked header value does not match the stored credential; enter the full value")
		}
		out[k] = old
	}
	return out, nil
}

// decodeTenantJSON reads one JSON object with only the documented fields. Any
// other field, including ones that would select an upstream command, is refused.
func decodeTenantJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, tenantMaxBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, "invalid_body", "A JSON object body is required.")
			return false
		}
		if strings.Contains(err.Error(), "unknown field") {
			writeJSONError(w, http.StatusBadRequest, "invalid_body", "Unknown field. Allowed fields: name, url, type, headers (tools: enabled).")
			return false
		}
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Request body must be a JSON object.")
		return false
	}
	if dec.More() {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Request body must be a single JSON object.")
		return false
	}
	return true
}

func writeTenantJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
