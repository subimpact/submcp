package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/subimpact/submcp/internal/db"
)

// ToolStore is the DB surface the aggregator needs (extracted for tests).
type ToolStore interface {
	GetActiveServersForNamespace(ctx context.Context, namespaceUUID string) ([]db.MCPServer, error)
	GetToolMappings(ctx context.Context, namespaceUUID string) ([]struct {
		Mapping db.NamespaceToolMapping
		Tool    db.Tool
	}, error)
	SyncTools(ctx context.Context, serverUUID string, tools []db.SyncToolInput) error
}

// Aggregator fans out MCP requests to all upstreams in a namespace and
// merges results:
//   - tool names prefixed: sanitizeName(serverName) + "__" + toolName
//   - per-server failure isolation (a dead upstream is skipped, others still respond)
//   - per-serverUUID raw-tool cache (60s TTL, single-flight refresh,
//     serve-stale on upstream failure) — tools/list does NOT hit every
//     upstream on every request (P1-9+P1-18)
//   - route map built in the same pass: prefixed name -> serverUUID,
//     first-server-wins on collision (P1-18)
//   - tools/list syncs discovered tools into the tools table (hash-gated, P1-5)
//   - tool filtering via namespace_tool_mappings (ACTIVE only) and
//     overrides applied per-request (admin changes immediate)
type Aggregator struct {
	pool *Pool
	db   ToolStore

	mu     sync.Mutex
	caches map[string]*nsCache // namespaceUUID -> servers (5s TTL)

	// P1-9: per-serverUUID raw tool cache.
	toolMu    sync.Mutex
	toolCache map[string]*toolCacheEntry
	inflight  map[string]*sync.WaitGroup // single-flight per server

	// P1-18: per-namespace route map (prefixed name -> serverUUID).
	routeMu sync.Mutex
	routes  map[string]*nsRoute

	// P1-5: tools sync hash-gate.
	syncMu     sync.Mutex
	syncHashes map[string]string
}

const (
	nsCacheTTL   = 5 * time.Second
	toolCacheTTL = 60 * time.Second
)

type nsCache struct {
	servers []db.MCPServer
	at      time.Time
}

type toolCacheEntry struct {
	tools []Tool // raw, unprefixed
	at    time.Time
}

type nsRoute struct {
	routeMap map[string]string // prefixed tool name -> serverUUID
	at       time.Time
}

// NewAggregator creates the fan-out engine.
func NewAggregator(pool *Pool, dbPool ToolStore) *Aggregator {
	return &Aggregator{
		pool:       pool,
		db:         dbPool,
		caches:     make(map[string]*nsCache),
		toolCache:  make(map[string]*toolCacheEntry),
		inflight:   make(map[string]*sync.WaitGroup),
		routes:     make(map[string]*nsRoute),
		syncHashes: make(map[string]string),
	}
}

var nameSanitizeRe = regexp.MustCompile(`[^a-zA-Z0-9_-]`)

// SanitizeName mirrors utils.ts:74 — strips everything outside [a-zA-Z0-9_-].
func SanitizeName(name string) string {
	return nameSanitizeRe.ReplaceAllString(name, "")
}

// ToolName builds the namespaced tool name: server__tool.
func ToolName(serverName, toolName string) string {
	return SanitizeName(serverName) + "__" + toolName
}

// ParseToolName splits on the FIRST __ only (nested prefixes survive).
func ParseToolName(name string) (server, tool string) {
	idx := strings.Index(name, "__")
	if idx < 0 {
		return name, ""
	}
	return name[:idx], name[idx+2:]
}

// ListTools returns the merged, filtered, overridden tool list for a namespace.
func (a *Aggregator) ListTools(ctx context.Context, namespaceUUID string) ([]Tool, error) {
	servers, err := a.getServers(ctx, namespaceUUID)
	if err != nil {
		return nil, err
	}

	// Build/refresh the route map (also warms the tool cache).
	if _, err := a.buildRouteMap(ctx, namespaceUUID, servers); err != nil {
		return nil, err
	}

	// Load tool mappings for filtering + overrides (per-request, so admin
	// changes are immediate — never cached).
	mappings, err := a.db.GetToolMappings(ctx, namespaceUUID)
	if err != nil {
		return nil, err
	}
	// Build lookup: serverUUID -> toolName -> mapping
	type mapKey struct{ server, tool string }
	overrideByKey := make(map[mapKey]db.NamespaceToolMapping)
	activeByKey := make(map[mapKey]bool)
	// Override names per server (P1-5 sync filter: tools whose name IS an
	// override name are not persisted — they'd duplicate the original).
	overrideNamesByServer := make(map[string]map[string]bool)
	for _, m := range mappings {
		k := mapKey{m.Mapping.MCPServerUUID, m.Tool.Name}
		overrideByKey[k] = m.Mapping
		activeByKey[k] = m.Mapping.Status == db.ServerStatusActive
		if m.Mapping.OverrideName != nil {
			if overrideNamesByServer[m.Mapping.MCPServerUUID] == nil {
				overrideNamesByServer[m.Mapping.MCPServerUUID] = map[string]bool{}
			}
			overrideNamesByServer[m.Mapping.MCPServerUUID][*m.Mapping.OverrideName] = true
		}
	}

	var (
		mu   sync.Mutex
		all  []Tool
		errs []string
		wg   sync.WaitGroup
	)
	for _, srv := range servers {
		if srv.Type != db.ServerTypeStreamableHTTP && srv.Type != db.ServerTypeSSE {
			continue // STDIO not supported in submcp v1
		}
		wg.Add(1)
		go func(s db.MCPServer) {
			defer wg.Done()
			tools, err := a.getServerTools(ctx, s, overrideNamesByServer[s.UUID])
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", s.Name, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, t := range tools {
				// DB stores tools WITHOUT the server prefix — strip it
				// back off for mapping lookups.
				prefix := SanitizeName(s.Name) + "__"
				unprefixed := strings.TrimPrefix(t.Name, prefix)
				k := mapKey{s.UUID, unprefixed}
				// Filter INACTIVE tools.
				if active, ok := activeByKey[k]; ok && !active {
					continue
				}
				// Apply overrides (only for tools WITH a DB mapping —
				// tools without mappings pass through untouched).
				if ov, ok := overrideByKey[k]; ok {
					if ov.OverrideName != nil {
						t.Name = *ov.OverrideName
					}
					if ov.OverrideDesc != nil {
						t.Description = ov.OverrideDesc
					}
					// P1-2: title override — top-level title, NOT
					// annotations.title. Mapped tools drop the UPSTREAM
					// title (parity with the original's wire output),
					// but an override title is applied as top-level.
					if ov.OverrideTitle != nil {
						t.Title = ov.OverrideTitle
					} else {
						t.Title = nil
					}
					// Strip legacy title hint from annotations (the
					// original always removes it to avoid conflicting
					// with the top-level title).
					if t.Annotations != nil {
						t.Annotations.Title = nil
						if t.Annotations.Title == nil &&
							t.Annotations.ReadOnlyHint == nil &&
							t.Annotations.DestructiveHint == nil &&
							t.Annotations.IDempotentHint == nil &&
							t.Annotations.OpenWorldHint == nil {
							t.Annotations = nil
						}
					}
					// Apply override_annotations (shallow merge, override
					// wins — mirrors mergeAnnotations).
					if len(ov.OverrideAnn) > 0 && string(ov.OverrideAnn) != "null" {
						var ann map[string]any
						if err := json.Unmarshal(ov.OverrideAnn, &ann); err == nil && len(ann) > 0 {
							if t.Annotations == nil {
								t.Annotations = &ToolAnnotations{}
							}
							applyAnnotationOverrides(t.Annotations, ann)
						}
					}
				}
				all = append(all, t)
			}
		}(srv)
	}
	wg.Wait()

	// Sort for deterministic output (original returns in server order; we
	// sort by name for stable parity comparisons).
	sort.Slice(all, func(i, j int) bool { return all[i].Name < all[j].Name })

	if len(all) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("all upstreams failed: %s", strings.Join(errs, "; "))
	}
	return all, nil
}

// CallTool routes a namespaced tool call to the right upstream.
func (a *Aggregator) CallTool(ctx context.Context, namespaceUUID, sessionID, toolName string, args json.RawMessage) (json.RawMessage, error) {
	serverName, originalName := ParseToolName(toolName)
	if serverName == "" {
		return nil, fmt.Errorf("invalid tool name %q: missing server prefix", toolName)
	}

	servers, err := a.getServers(ctx, namespaceUUID)
	if err != nil {
		return nil, err
	}

	// Route via the map (build on demand if stale/missing — P1-18
	// build-on-demand for CallTool-before-ListTools).
	serverUUID := ""
	if routeMap, err := a.buildRouteMap(ctx, namespaceUUID, servers); err == nil {
		serverUUID = routeMap[toolName]
	}
	if serverUUID == "" {
		// Fall back to prefix matching (server may be new, or the tool
		// was added upstream after the last route build).
		for i := range servers {
			if SanitizeName(servers[i].Name) == serverName {
				serverUUID = servers[i].UUID
				break
			}
		}
	}
	if serverUUID == "" {
		return nil, fmt.Errorf("no active server matching %q in namespace", serverName)
	}

	var target *db.MCPServer
	for i := range servers {
		if servers[i].UUID == serverUUID {
			target = &servers[i]
			break
		}
	}
	if target == nil {
		return nil, fmt.Errorf("no active server matching %q in namespace", serverName)
	}
	if target.URL == nil || *target.URL == "" {
		return nil, fmt.Errorf("server %q has no URL configured", target.Name)
	}

	client, err := a.pool.Acquire(ctx, sessionID, target.UUID, func() (*UpstreamClient, error) {
		cfg := UpstreamConfig{
			Name:        target.Name,
			URL:         *target.URL,
			BearerToken: deref(target.BearerToken),
			Headers:     parseHeaders(target.Headers),
			Timeout:     60 * time.Second,
		}
		c := NewUpstreamClient(cfg)
		if err := c.Connect(ctx); err != nil {
			return nil, err
		}
		return c, nil
	})
	if err != nil {
		return nil, fmt.Errorf("acquire upstream %s: %w", target.Name, err)
	}
	defer a.pool.Release(sessionID, target.UUID, client)

	return client.CallTool(ctx, originalName, args)
}

// getServerTools returns PREFIXED tools for a server, using the 60s cache.
// Cache miss: fetch from upstream (single-flight per server), sync to DB
// (hash-gated), cache. Upstream failure with stale cache: serve stale.
func (a *Aggregator) getServerTools(ctx context.Context, s db.MCPServer, overrideNames map[string]bool) ([]Tool, error) {
	// Fast path: fresh cache.
	a.toolMu.Lock()
	if e, ok := a.toolCache[s.UUID]; ok && time.Since(e.at) < toolCacheTTL {
		tools := prefixTools(s.Name, e.tools)
		a.toolMu.Unlock()
		return tools, nil
	}
	a.toolMu.Unlock()

	// Single-flight: one fetch per server at a time.
	a.toolMu.Lock()
	wg, ok := a.inflight[s.UUID]
	if !ok {
		wg = &sync.WaitGroup{}
		wg.Add(1)
		a.inflight[s.UUID] = wg
	}
	a.toolMu.Unlock()

	if ok {
		// Another goroutine is fetching; wait for it, then serve cache.
		wg.Wait()
		a.toolMu.Lock()
		e, ok := a.toolCache[s.UUID]
		a.toolMu.Unlock()
		if ok {
			return prefixTools(s.Name, e.tools), nil
		}
		return nil, fmt.Errorf("server %q tools unavailable", s.Name)
	}

	// We are the fetcher.
	defer func() {
		a.toolMu.Lock()
		delete(a.inflight, s.UUID)
		a.toolMu.Unlock()
		wg.Done()
	}()

	tools, err := a.fetchServerTools(ctx, s, overrideNames)
	if err != nil {
		// Serve stale if we have it.
		a.toolMu.Lock()
		e, hasStale := a.toolCache[s.UUID]
		a.toolMu.Unlock()
		if hasStale {
			slog.Warn("upstream tools/list failed; serving stale", "server", s.Name, "err", err)
			return prefixTools(s.Name, e.tools), nil
		}
		return nil, err
	}

	a.toolMu.Lock()
	a.toolCache[s.UUID] = &toolCacheEntry{tools: tools, at: time.Now()}
	a.toolMu.Unlock()
	return prefixTools(s.Name, tools), nil
}

// fetchServerTools fetches raw (unprefixed) tools from upstream and syncs
// them to the DB (P1-5, hash-gated, non-fatal).
func (a *Aggregator) fetchServerTools(ctx context.Context, s db.MCPServer, overrideNames map[string]bool) ([]Tool, error) {
	if s.URL == nil || *s.URL == "" {
		return nil, fmt.Errorf("server %q has no URL configured", s.Name)
	}
	// Use a per-call session id (pool handles reuse).
	sessionID := "list-" + s.UUID
	client, err := a.pool.Acquire(ctx, sessionID, s.UUID, func() (*UpstreamClient, error) {
		cfg := UpstreamConfig{
			Name:        s.Name,
			URL:         *s.URL,
			BearerToken: deref(s.BearerToken),
			Headers:     parseHeaders(s.Headers),
			Timeout:     60 * time.Second,
		}
		c := NewUpstreamClient(cfg)
		if err := c.Connect(ctx); err != nil {
			return nil, err
		}
		return c, nil
	})
	if err != nil {
		return nil, err
	}
	defer a.pool.Release(sessionID, s.UUID, client)

	tools, err := client.ListTools(ctx)
	if err != nil {
		return nil, err
	}

	// P1-5: persist discovered tools (hash-gated, non-fatal). Mirrors the
	// original's proxy sync: only sync when the tool-name set changed,
	// filter out override names, never fail the response on DB errors.
	a.syncTools(ctx, s, tools, overrideNames)
	return tools, nil
}

// applyAnnotationOverrides merges override annotation values into a tool's
// annotations (shallow merge, override wins — mirrors the original's
// mergeAnnotations). Unknown keys are ignored (the wire shape only carries
// the known hint fields).
func applyAnnotationOverrides(ann *ToolAnnotations, overrides map[string]any) {
	if v, ok := overrides["readOnlyHint"].(bool); ok {
		ann.ReadOnlyHint = &v
	}
	if v, ok := overrides["destructiveHint"].(bool); ok {
		ann.DestructiveHint = &v
	}
	if v, ok := overrides["idempotentHint"].(bool); ok {
		ann.IDempotentHint = &v
	}
	if v, ok := overrides["openWorldHint"].(bool); ok {
		ann.OpenWorldHint = &v
	}
	// title in override_annotations is a legacy hint — the original
	// strips it; we ignore it too (top-level title is the source of truth).
}

// prefixTools returns a copy of tools with names prefixed server__tool.
func prefixTools(serverName string, tools []Tool) []Tool {
	out := make([]Tool, len(tools))
	for i, t := range tools {
		out[i] = t
		out[i].Name = ToolName(serverName, t.Name)
	}
	return out
}

// buildRouteMap builds (or refreshes) the per-namespace route map:
// prefixed tool name -> serverUUID. First-server-wins on collision (log).
// Also warms the tool cache. TTL 5s (folded nsCache).
func (a *Aggregator) buildRouteMap(ctx context.Context, namespaceUUID string, servers []db.MCPServer) (map[string]string, error) {
	a.routeMu.Lock()
	if r, ok := a.routes[namespaceUUID]; ok && time.Since(r.at) < nsCacheTTL {
		a.routeMu.Unlock()
		return r.routeMap, nil
	}
	a.routeMu.Unlock()

	routeMap := make(map[string]string)
	var (
		mu   sync.Mutex
		errs []string
		wg   sync.WaitGroup
	)
	for _, srv := range servers {
		if srv.Type != db.ServerTypeStreamableHTTP && srv.Type != db.ServerTypeSSE {
			continue
		}
		wg.Add(1)
		go func(s db.MCPServer) {
			defer wg.Done()
			tools, err := a.getServerTools(ctx, s, nil)
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Sprintf("%s: %v", s.Name, err))
				mu.Unlock()
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for _, t := range tools {
				if _, exists := routeMap[t.Name]; exists {
					slog.Warn("tool name collision; first server wins",
						"tool", t.Name, "server", s.Name)
					continue
				}
				routeMap[t.Name] = s.UUID
			}
		}(srv)
	}
	wg.Wait()

	a.routeMu.Lock()
	a.routes[namespaceUUID] = &nsRoute{routeMap: routeMap, at: time.Now()}
	a.routeMu.Unlock()

	if len(routeMap) == 0 && len(errs) > 0 {
		return nil, fmt.Errorf("all upstreams failed: %s", strings.Join(errs, "; "))
	}
	return routeMap, nil
}

// toolNamesHash mirrors tools-sync-cache.ts: sha256 of the sorted names
// joined with "|". Order-independent and stable — the sync gate.
func toolNamesHash(names []string) string {
	sorted := make([]string, len(names))
	copy(sorted, names)
	sort.Strings(sorted)
	h := sha256.Sum256([]byte(strings.Join(sorted, "|")))
	return hex.EncodeToString(h[:])
}

// syncTools persists discovered tools for a server. Hash-gated on the sorted
// tool-name set (sha256, in-memory) so unchanged servers skip DB writes;
// override-named tools are filtered out (they'd duplicate the original);
// DB errors are logged and swallowed — tools/list must never fail because
// persistence failed (the original's behavior).
func (a *Aggregator) syncTools(ctx context.Context, s db.MCPServer, tools []Tool, overrideNames map[string]bool) {
	names := make([]string, len(tools))
	for i, t := range tools {
		names[i] = t.Name
	}
	hashHex := toolNamesHash(names)

	a.syncMu.Lock()
	if a.syncHashes[s.UUID] == hashHex {
		a.syncMu.Unlock()
		return
	}
	a.syncMu.Unlock()

	// Filter out tools whose name is an override name for this server
	// (the original's filterOutOverrideTools; fail-safe: persist on doubt).
	toSave := make([]db.SyncToolInput, 0, len(tools))
	for _, t := range tools {
		if overrideNames != nil && overrideNames[t.Name] {
			continue
		}
		desc := ""
		if t.Description != nil {
			desc = *t.Description
		}
		toSave = append(toSave, db.SyncToolInput{
			Name:        t.Name,
			Description: desc,
			InputSchema: t.InputSchema,
		})
	}

	if err := a.db.SyncTools(ctx, s.UUID, toSave); err != nil {
		slog.Warn("tools sync failed", "server", s.Name, "err", err)
		return
	}

	a.syncMu.Lock()
	a.syncHashes[s.UUID] = hashHex
	a.syncMu.Unlock()
}

func (a *Aggregator) getServers(ctx context.Context, namespaceUUID string) ([]db.MCPServer, error) {
	a.mu.Lock()
	if c, ok := a.caches[namespaceUUID]; ok && time.Since(c.at) < nsCacheTTL {
		a.mu.Unlock()
		return c.servers, nil
	}
	a.mu.Unlock()

	servers, err := a.db.GetActiveServersForNamespace(ctx, namespaceUUID)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.caches[namespaceUUID] = &nsCache{servers: servers, at: time.Now()}
	a.mu.Unlock()
	return servers, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func parseHeaders(raw json.RawMessage) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}
