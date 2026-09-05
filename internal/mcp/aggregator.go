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

// Aggregator fans out MCP requests to all upstreams in a namespace and
// merges results:
//   - tool names prefixed: sanitizeName(serverName) + "__" + toolName
//   - per-server failure isolation (a dead upstream is skipped, others still respond)
//   - tools/list syncs discovered tools into the tools table (hash-gated)
//   - tool filtering via namespace_tool_mappings (ACTIVE only)
//   - tool overrides (name/title/description/annotations)
type Aggregator struct {
	pool   *Pool
	db     *db.Pool
	mu     sync.Mutex
	caches map[string]*nsCache

	// Tools sync hash-gate (P1-5): serverUUID -> sha256 of sorted tool
	// names. Mirrors tools-sync-cache.ts — only sync when names changed.
	syncMu     sync.Mutex
	syncHashes map[string]string
}

type nsCache struct {
	servers []db.MCPServer
	at      time.Time
}

// NewAggregator creates the fan-out engine.
func NewAggregator(pool *Pool, dbPool *db.Pool) *Aggregator {
	return &Aggregator{
		pool:       pool,
		db:         dbPool,
		caches:     make(map[string]*nsCache),
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

	// Load tool mappings for filtering + overrides.
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
		mu     sync.Mutex
		all    []Tool
		errs   []string
		wg     sync.WaitGroup
	)
	for _, srv := range servers {
		if srv.Type != db.ServerTypeStreamableHTTP && srv.Type != db.ServerTypeSSE {
			continue // STDIO not supported in submcp v1
		}
		wg.Add(1)
		go func(s db.MCPServer) {
			defer wg.Done()
			tools, err := a.listFromServer(ctx, s, overrideNamesByServer[s.UUID])
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
					if ov.OverrideTitle != nil && t.Annotations == nil {
						t.Annotations = &ToolAnnotations{}
					}
					if ov.OverrideTitle != nil {
						title := *ov.OverrideTitle
						t.Annotations.Title = &title
					}
					// Strip legacy title hint from annotations.
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
					// Mapped tools lose top-level title entirely (the
					// original's Tool schema has no title field — it's
					// dropped on serialization). Unmapped tools pass
					// through untouched.
					t.Title = nil
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
	var target *db.MCPServer
	for i := range servers {
		if SanitizeName(servers[i].Name) == serverName {
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

func (a *Aggregator) listFromServer(ctx context.Context, s db.MCPServer, overrideNames map[string]bool) ([]Tool, error) {
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

	// Prefix tool names.
	for i := range tools {
		tools[i].Name = ToolName(s.Name, tools[i].Name)
	}
	return tools, nil
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
	if c, ok := a.caches[namespaceUUID]; ok && time.Since(c.at) < 5*time.Second {
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
