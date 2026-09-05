package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// EndpointStore is the subset of the DB the server needs. Extracted as an
// interface (P2-10) so handlers can be tested with httptest and fakes
// instead of a live Postgres.
type EndpointStore interface {
	GetEndpointByName(ctx context.Context, name string) (*db.Endpoint, error)
	ListEndpoints(ctx context.Context) ([]db.Endpoint, error)
}

// Server is the HTTP front for the MCP gateway.
// Serves:
//   - POST/GET/DELETE /metamcp/:endpoint/mcp  (streamable HTTP)
//   - GET  /metamcp/:endpoint/sse             (legacy SSE)
//   - POST /metamcp/:endpoint/message         (SSE message endpoint)
//   - GET  /health
type Server struct {
	db        EndpointStore
	agg       *Aggregator
	pool      *Pool
	auth      *Auth
	sessions  *SessionStore
	startTime time.Time
}

// NewServer wires the HTTP server. sessionTTL is the downstream session
// lifetime (0 = no expiry; P1-4 default 1h).
func NewServer(dbPool EndpointStore, agg *Aggregator, pool *Pool, auth *Auth, sessionTTL time.Duration) *Server {
	return &Server{
		db:        dbPool,
		agg:       agg,
		pool:      pool,
		auth:      auth,
		sessions:  NewSessionStore(sessionTTL),
		startTime: time.Now(),
	}
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/metamcp/", s.handleMetamcp)

	return withCORS(mux)
}

// withCORS enables browser MCP clients (P2-5a). Mirrors the original's
// cors({ origin: true, credentials: true, methods: [GET,POST,DELETE,OPTIONS],
// allowedHeaders: [Content-Type, mcp-session-id, Authorization, X-API-Key] }).
// Origin is echoed (NOT "*" — "*" with credentials is invalid per spec);
// OPTIONS preflights are answered 204 with the allow headers.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, mcp-session-id, Authorization, X-API-Key")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":  "ok",
		"uptime":  time.Since(s.startTime).String(),
		"version": "0.1.0",
	})
}

// handleMetamcp routes /metamcp/:endpoint/... paths.
func (s *Server) handleMetamcp(w http.ResponseWriter, r *http.Request) {
	// Path: /metamcp/<endpoint>/<rest...>
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/metamcp/"), "/")
	if len(parts) < 1 || parts[0] == "" {
		// Endpoint enumeration (parity with original S4 behavior).
		s.handleEndpointList(w, r)
		return
	}
	endpointName := parts[0]
	rest := ""
	if len(parts) > 1 {
		rest = strings.Join(parts[1:], "/")
	}

	ep, err := s.db.GetEndpointByName(r.Context(), endpointName)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	if ep == nil {
		// Exact fixture shape: error + message + timestamp (ms precision).
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]any{
			"error":     "Endpoint not found",
			"message":   fmt.Sprintf("No endpoint found with name: %s", endpointName),
			"timestamp": time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		})
		return
	}

	// Auth (unless the endpoint disables it).
	if ep.EnableAPIKeyAuth {
		if !s.auth.Authenticate(w, r, ep) {
			// Auth middleware already wrote the response.
			return
		}
	}

	switch {
	case rest == "mcp":
		s.handleStreamableHTTP(w, r, ep)
	case rest == "sse":
		s.handleSSE(w, r, ep)
	case rest == "message":
		s.handleSSEMessage(w, r, ep)
	default:
		writeJSONError(w, http.StatusNotFound, "not_found", "Unknown path")
	}
}

// handleEndpointList mirrors the original unauthenticated enumeration, but
// strips sensitive fields (P1-17): user_id, namespace_uuid, and
// enable_api_key_auth are NOT exposed to unauthenticated callers.
func (s *Server) handleEndpointList(w http.ResponseWriter, r *http.Request) {
	eps, err := s.db.ListEndpoints(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Database error")
		return
	}
	type publicEndpoint struct {
		UUID              string    `json:"uuid"`
		Name              string    `json:"name"`
		Description       *string   `json:"description"`
		UseQueryParamAuth bool      `json:"use_query_param_auth"`
		CreatedAt         time.Time `json:"created_at"`
		UpdatedAt         time.Time `json:"updated_at"`
		EnableOAuth       bool      `json:"enable_oauth"`
	}
	out := make([]publicEndpoint, 0, len(eps))
	for _, e := range eps {
		out = append(out, publicEndpoint{
			UUID:              e.UUID,
			Name:              e.Name,
			Description:       e.Description,
			UseQueryParamAuth: e.UseQueryParamAuth,
			CreatedAt:         e.CreatedAt,
			UpdatedAt:         e.UpdatedAt,
			EnableOAuth:       e.EnableOAuth,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"endpoints": out})
}

// handleStreamableHTTP implements the MCP streamable HTTP transport.
func (s *Server) handleStreamableHTTP(w http.ResponseWriter, r *http.Request, ep *db.Endpoint) {
	switch r.Method {
	case http.MethodPost:
		s.handlePost(w, r, ep)
	case http.MethodGet:
		// GET = SSE stream for a session (streamable HTTP spec).
		s.handleStreamableGET(w, r, ep)
	case http.MethodDelete:
		s.handleDelete(w, r, ep)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed")
	}
}

// writeSessionNotFound writes the exact fixture shape for an unknown session.
// The available_sessions field is kept for wire-shape parity but always
// returns an empty list (never leaks live session IDs — security fix).
func (s *Server) writeSessionNotFound(w http.ResponseWriter, sessionID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]any{
		"error":             "Session not found",
		"message":           fmt.Sprintf("Transport not found for sessionId %s", sessionID),
		"available_sessions": []string{},
		"timestamp":         time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
	})
}

// handlePost processes a JSON-RPC request (initialize, tools/list, tools/call).
func (s *Server) handlePost(w http.ResponseWriter, r *http.Request, ep *db.Endpoint) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Failed to read body")
		return
	}

	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse_error", "Invalid JSON-RPC")
		return
	}

	// Session handling.
	sessionID := r.Header.Get("mcp-session-id")

	// JSON-RPC notifications (no id) must NOT receive a response (P1-8).
	// Per the streamable HTTP spec, return 202 Accepted with an empty
	// body for notification-only POSTs.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// P2-6: non-initialize requests MUST carry a session id. Inventing a
	// UUID here would produce a misleading 404 "Session not found" for a
	// client that never initialized — a 400 is the honest answer.
	if sessionID == "" && req.Method != "initialize" {
		writeJSONError(w, http.StatusBadRequest, "missing_session",
			"mcp-session-id header is required for non-initialize requests")
		return
	}

	switch req.Method {
	case "initialize":
		// Always mint a fresh session ID on initialize. Never trust a
		// client-supplied mcp-session-id header here: rebinding an
		// existing session to a different endpoint is a hijack vector
		// (P0-1).
		sessionID = newUUID()
		result := s.handleInitialize(r.Context(), ep, req)
		s.sessions.Put(sessionID, ep.NamespaceUUID, ep.UUID)
		w.Header().Set("mcp-session-id", sessionID)
		writeSSE(w, r, newResponse(req.ID, result, nil))
	case "tools/list":
		nsUUID, ok := s.sessions.Get(sessionID, ep.UUID)
		if !ok {
			s.writeSessionNotFound(w, sessionID)
			return
		}
		tools, err := s.agg.ListTools(r.Context(), nsUUID)
		if err != nil {
			writeSSE(w, r, newResponse(req.ID, nil, &RPCError{Code: CodeInternalError, Message: err.Error()}))
			return
		}
		writeSSE(w, r, newResponse(req.ID, map[string]any{"tools": tools}, nil))
	case "tools/call":
		nsUUID, ok := s.sessions.Get(sessionID, ep.UUID)
		if !ok {
			s.writeSessionNotFound(w, sessionID)
			return
		}
		var params CallToolParams
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &params)
		}
		result, err := s.agg.CallTool(r.Context(), nsUUID, sessionID, params.Name, params.Arguments)
		if err != nil {
			writeSSE(w, r, newResponse(req.ID, nil, &RPCError{Code: CodeInternalError, Message: err.Error()}))
			return
		}
		writeSSE(w, r, newResponse(req.ID, result, nil))
	case "ping":
		writeSSE(w, r, newResponse(req.ID, map[string]any{}, nil))
	default:
		writeSSE(w, r, newResponse(req.ID, nil, &RPCError{Code: CodeMethodNotFound, Message: "Method not found: " + req.Method}))
	}
}

func (s *Server) handleInitialize(ctx context.Context, ep *db.Endpoint, req Request) map[string]any {
	// P1-10: protocol version negotiation — echo the client's version if
	// we support it, else fall back to 2025-03-26.
	version := "2025-03-26"
	var params InitializeParams
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &params)
	}
	if params.ProtocolVersion != "" && supportedProtocolVersions[params.ProtocolVersion] {
		version = params.ProtocolVersion
	}
	return map[string]any{
		"protocolVersion": version,
		// Advertise tools only (P1-10): submcp implements tools/list and
		// tools/call; prompts/resources are not implemented, so claiming
		// them would be a lie to clients.
		"capabilities": map[string]any{
			"tools": map[string]any{},
		},
		"serverInfo": map[string]string{
			"name":    "submcp",
			"version": "0.1.0",
		},
	}
}

// supportedProtocolVersions are the MCP protocol versions submcp can speak.
var supportedProtocolVersions = map[string]bool{
	"2024-11-05": true,
	"2025-03-26": true,
	"2025-06-18": true,
}

// SweepSessions removes expired downstream sessions and returns their IDs
// so the caller can release pool clients (P1-4).
func (s *Server) SweepSessions() []string {
	return s.sessions.Sweep()
}

// handleStreamableGET opens an SSE stream for an existing session.
func (s *Server) handleStreamableGET(w http.ResponseWriter, r *http.Request, ep *db.Endpoint) {
	sessionID := r.Header.Get("mcp-session-id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Missing mcp-session-id header")
		return
	}
	if _, ok := s.sessions.Get(sessionID, ep.UUID); !ok {
		s.writeSessionNotFound(w, sessionID)
		return
	}
	// Keep the stream open (heartbeat) until client disconnects.
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Heartbeat comment keeps intermediaries from closing the stream.
			_, _ = io.WriteString(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// handleDelete terminates a session.
func (s *Server) handleDelete(w http.ResponseWriter, r *http.Request, ep *db.Endpoint) {
	sessionID := r.Header.Get("mcp-session-id")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Missing mcp-session-id header")
		return
	}
	// Endpoint check: a caller may only delete a session that belongs to
	// the endpoint they are authenticated against (P0-1).
	if _, ok := s.sessions.Get(sessionID, ep.UUID); !ok {
		s.writeSessionNotFound(w, sessionID)
		return
	}
	s.sessions.Delete(sessionID)
	s.pool.ReleaseSession(sessionID)
	w.WriteHeader(http.StatusOK)
}

// handleSSE implements the legacy SSE transport: GET /sse opens a stream
// and emits an endpoint event with a message URL.
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request, ep *db.Endpoint) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", "Streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	sessionID := newUUID()
	s.sessions.Put(sessionID, ep.NamespaceUUID, ep.UUID)

	// Emit the endpoint event (parity with captured fixture).
	msgURL := fmt.Sprintf("/metamcp/%s/message?sessionId=%s", ep.Name, sessionID)
	_, _ = io.WriteString(w, "event: endpoint\n")
	_, _ = io.WriteString(w, "data: "+msgURL+"\n\n")
	flusher.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			s.sessions.Delete(sessionID)
			s.pool.ReleaseSession(sessionID)
			return
		case <-ticker.C:
			_, _ = io.WriteString(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

// handleSSEMessage processes POSTs to the SSE message endpoint.
func (s *Server) handleSSEMessage(w http.ResponseWriter, r *http.Request, ep *db.Endpoint) {
	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Missing sessionId query param")
		return
	}
	nsUUID, ok := s.sessions.Get(sessionID, ep.UUID)
	if !ok {
		s.writeSessionNotFound(w, sessionID)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Failed to read body")
		return
	}
	var req Request
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "parse_error", "Invalid JSON-RPC")
		return
	}

	var result json.RawMessage
	switch req.Method {
	case "initialize":
		// Legacy SSE clients also send initialize (the SDK transport
		// handles it). Echo the negotiated version, tools-only
		// capabilities (P1-10 parity with the streamable path).
		init := s.handleInitialize(r.Context(), ep, req)
		result, _ = json.Marshal(init)
	case "tools/list":
		tools, err := s.agg.ListTools(r.Context(), nsUUID)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		result, _ = json.Marshal(map[string]any{"tools": tools})
	case "tools/call":
		var params CallToolParams
		if len(req.Params) > 0 {
			_ = json.Unmarshal(req.Params, &params)
		}
		res, err := s.agg.CallTool(r.Context(), nsUUID, sessionID, params.Name, params.Arguments)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		result = res
	case "ping":
		result = json.RawMessage(`{}`)
	default:
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_found", "Method not found: "+req.Method)
		return
	}

	// Notifications (no id) get 202 with an empty body (P1-8 parity).
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      req.ID,
		"result":  json.RawMessage(result),
	})
}

// --- helpers ---

func newResponse(id json.RawMessage, result any, rpcErr *RPCError) Response {
	resp := Response{JSONRPC: "2.0", ID: id, Error: rpcErr}
	if result != nil {
		b, _ := json.Marshal(result)
		resp.Result = b
	}
	return resp
}

// writeSSE writes a JSON-RPC response as an SSE event (parity with the
// original streamable-http.ts which always uses SSE framing).
func writeSSE(w http.ResponseWriter, r *http.Request, resp Response) {
	// If the client explicitly asked for JSON (no SSE), return plain JSON.
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/event-stream") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	b, _ := json.Marshal(resp)
	_, _ = io.WriteString(w, "event: message\n")
	_, _ = io.WriteString(w, "data: "+string(b)+"\n\n")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func writeJSONError(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{
		"error":             code,
		"error_description": msg,
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
	})
}

// SessionStore tracks downstream sessions -> namespace + endpoint.
// Sessions are bound to the endpoint they were created on so a session
// from one endpoint cannot be replayed against another (cross-tenant
// isolation — security fix).
//
// P1-4: sessions carry a TTL (default 1h). Expiry is enforced lazily on
// Get and eagerly by Sweep (which also releases the session's pool
// clients). TTL 0 = no expiry (only when explicitly configured).
type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]sessionInfo // sessionID -> info
	ttl      time.Duration
}

type sessionInfo struct {
	namespaceUUID string
	endpointUUID  string
	createdAt     time.Time
}

func NewSessionStore(ttl time.Duration) *SessionStore {
	return &SessionStore{sessions: make(map[string]sessionInfo), ttl: ttl}
}

func (s *SessionStore) Put(sessionID, nsUUID, epUUID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[sessionID] = sessionInfo{namespaceUUID: nsUUID, endpointUUID: epUUID, createdAt: time.Now()}
}

// Get returns the namespace for a session if it exists AND was created on
// the given endpoint AND has not expired. Returns ok=false on any mismatch.
func (s *SessionStore) Get(sessionID, epUUID string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.sessions[sessionID]
	if !ok || info.endpointUUID != epUUID {
		return "", false
	}
	if s.ttl > 0 && time.Since(info.createdAt) > s.ttl {
		delete(s.sessions, sessionID)
		return "", false
	}
	return info.namespaceUUID, true
}

func (s *SessionStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sessionID)
}

// Sweep removes expired sessions and returns their IDs so the caller can
// release pool clients. No-op when TTL is 0.
func (s *SessionStore) Sweep() []string {
	if s.ttl <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var expired []string
	now := time.Now()
	for id, info := range s.sessions {
		if now.Sub(info.createdAt) > s.ttl {
			delete(s.sessions, id)
			expired = append(expired, id)
		}
	}
	return expired
}
