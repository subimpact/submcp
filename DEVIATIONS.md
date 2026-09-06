# DEVIATIONS.md — submcp vs original MetaMCP

Status: **parity formally abandoned** (roadmap decision gate 3). The Go
rewrite deliberately diverges from the original TypeScript MetaMCP in the
ways listed below. This file is the single source of truth for what is
intentional and what is not. Golden parity tests (internal/httpapi) pin
the wire behaviors that MUST match; anything in this file is exempt.

Audit basis: claudy deep-audit 2026-09-05 (34KB, 32 findings) + source
verification of every claim. Fixtures: `fixtures/raw/` (captured from the
original on 2026-08-31).

---

## A. Intentional deviations (approved)

| # | Area | Deviation | Rationale |
|---|------|-----------|-----------|
| 1 | P1-2 | Title override goes to TOP-LEVEL `title`, never `annotations.title`; legacy `annotations.title` stripped for mapped tools | The original's own middleware strips the legacy hint; top-level is the modern MCP shape |
| 2 | P1-10 | Capabilities advertise TOOLS ONLY | The original claims prompts/resources it doesn't implement; lying to clients is worse |
| 3 | P2-6 | Missing `mcp-session-id` on non-initialize → 400 `{error:"missing_session",...}` | The original's SDK answers 400 too, but with a JSON-RPC error object; our body is the documented shape. (The original also leaks a transport per such request — we don't.) |
| 4 | P1-4 | Session TTL default 1h (0 = no expiry only when explicit) | Original: infinite sessions |
| 5 | P2-5a | CORS echoes Origin (never `*` with credentials) | `*` + credentials is invalid per spec |
| 6 | P1-17 | `GET /metamcp/` returns a DIFFERENT shape than the original: `{endpoints:[{uuid,name,description,use_query_param_auth,created_at,updated_at,enable_oauth}]}` | The original returns `{service,version,description,endpoints:[{name,description,namespace,endpoints:{mcp,sse,api,openapi}}]}`. Neither leaks user_id/namespace_uuid/enable_api_key_auth — the original never exposed those on this route. Our shape is the admin-oriented one; the original's `namespace`/`endpoints` sub-objects are dropped. |
| 7 | P1-12 | tools/list pagination follows nextCursor with 50-page cap | Original: no cap (infinite-loop risk) |
| 8 | P1-7 | Legacy SSE kept + fixed: initialize handled, notifications → 202, responses delivered OVER the stream (event:message) with 202 on POST | Log evidence: 0/1166 hits on /sse in 72h. The response-over-stream behavior matches the SDK's `SSEServerTransport.handlePostMessage` — the original's actual transport semantics |
| 9 | P1-3 | SSRF guard: 169.254/16 + loopback + link-local ALWAYS blocked; RFC1918 gated on `ALLOW_PRIVATE_UPSTREAMS` (default ON self-hosted) | Cloud metadata + loopback are never legitimate upstreams. NOTE: guard is literal-IP only — hostnames that resolve to blocked IPs are not caught (documented limitation) |
| 10 | P2-13 | API keys stored/compared as SHA-256 hash (`key_hash`); plaintext never in WHERE clauses | DB leak no longer exposes usable keys |
| 11 | P2-4 | Admin API returns generic `internal_error` (real error logged server-side) | Original leaks `err.Error()` to callers. Exception: the test-connection endpoint returns the upstream error — that IS the result |
| 12 | P2-3 | `ADMIN_IP_ALLOWLIST` restricts `/api/admin/*` source IPs | Defense in depth. NOTE: `/api/admin/login` + `/logout` are NOT allowlisted (they must be reachable to authenticate); the allowlist gates everything after login. X-Forwarded-For is trusted — deploy behind Traefik which overwrites it |
| 13 | P2-11 | Endpoint names restricted to `[a-zA-Z0-9_-]` max 64 | Names become URL path segments |
| 14 | P2-2 | `inputSchema` defaults to `{"type":"object"}` when upstream omits it | MCP spec requires an object; never emit null |
| 15 | P1-5 | Tools persistence hash-gated (sha256 of sorted names) | Only sync when the tool-name set changed |
| 16 | P1-9/P1-18 | Per-server tool cache (60s) + route map | Original: no cache (cold tools/list ~950ms; ours warm ~46ms) |
| 17 | P1-1/P1-11 | SSE parser rewrite: multi-line data, notification skip, apify `id:` field is Last-Event-ID not correlation | The original's parser dropped apify's events (137 vs 143 tools) |
| 18 | P1-6 | Circuit breaker (5 failures → open 30s → half-open probe) + `error_status` quarantine | Original: no breaker; `error_status` existed but nothing wrote it |
| 19 | P1-13 | `POSTGRES_SSLMODE` configurable | Original: hardcoded |
| 20 | P1-14 | Request logging (method/path/status/duration/ip/ua) | Original: none. NOTE: no request-ID header is emitted (the log line is the correlation point) |
| 21 | P2-7 | ReadTimeout 30s + IdleTimeout 120s; NO WriteTimeout | WriteTimeout would kill long-lived SSE streams |
| 22 | P2-8 | Dockerfile runs as non-root (uid 10001) | Least privilege |
| 23 | P2-14 | Upstream transport: idle pool 64/16, handshake + response-header timeouts | Default transport caps idle conns at 2/host — a gateway bottleneck |
| 24 | P2-10 | UI depends on a `Store` interface, not `*db.Pool` | Testability |
| 25 | P2-12 | SPA: all `api()` calls wrapped in try/catch | No unhandled rejections |
| 26 | P2-9 | staticcheck clean | Dead code removed |

## B. Deviations missing from the original list (documented now)

| # | Area | Deviation | Note |
|---|------|-----------|------|
| 27 | Security | `available_sessions` in session-not-found 404 is ALWAYS `[]` | The original leaks every live session ID. Single most valuable security fix in the rewrite |
| 28 | Security | Sessions bound to creating endpoint; initialize always mints a fresh ID (client-supplied header ignored) | P0-1: cross-endpoint session replay is impossible |
| 29 | Security | Tenant scoping mirrors `checkApiKeyAccess`: public key (user_id NULL) → private endpoint = 403; private key → other's endpoint = 403 | P0-1.5 |
| 30 | Security | OAuth-only endpoints → 401 challenge + deny | submcp does not implement OAuth; silent allow would be a bypass (P0-1.4) |
| 31 | Security | Security headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-XSS-Protection: 0` | The original's captured values differ (`strict-origin-when-cross-origin`, `1; mode=block`, plus a CSP we don't emit). Ours are the modern-safe set |
| 32 | Ops | Global per-IP rate limit 60 req/min (token bucket) | The original has NO global limit. **Most likely deviation to cause a production incident** — high-throughput MCP clients will 429. Tune via code if needed |
| 33 | Ops | `/metrics` (expvar) is UNAUTHENTICATED | Exposes upstream names + per-server call/failure counts. Behind Traefik; consider gating if public exposure is a concern |
| 34 | Ops | `/ready` endpoint (PG ping + pool stats) | New surface for orchestrators |
| 35 | Ops | Admin UI + `/api/public/stats` (unauthenticated, non-sensitive) | New surface; the original had no admin console |
| 36 | Ops | SSE stream cap: streamable-GET streams end after 24h | Original: infinite streams |
| 37 | Ops | Namespace server list cached 5s | Original: DB hit per request |
| 38 | Wire | `Authorization: ApiKey <key>` accepted as a key form | The original only accepts `Bearer`; this is a superset |
| 39 | DB | `SyncTools` runs in a transaction | Original: per-row writes; ours is atomic |
| 40 | Scope | STDIO upstreams unsupported | Original supports stdio servers; submcp v1 is streamable-HTTP + SSE only |
| 41 | Scope | prompts/resources handlers NOT implemented (`prompts/list`, `resources/list`, etc. → -32601) | Consistent with tools-only capabilities (#2) |
| 42 | Scope | OpenAPI/REST surface removed (`/metamcp/:ep/api/*`, `/openapi.json`) | Not part of the MCP wire contract |
| 43 | Ops | `error_status` auto-reset to NONE on every success | The original's server-error-tracker writes only on state change; ours writes on every success (cheap, but a DB write per call) |
| 44 | Config | MCP_TIMEOUT / SESSION_LIFETIME read from ENV at boot | The original reads them from the `config` table at request time; admin changes to those values no longer take effect without restart |
| 45 | Wire | `tools/list` result ordering: alphabetical by name | The original returns server-completion order (nondeterministic). Ours is deterministic — a wire change, defensible |
| 46 | Wire | `_meta` from client params is NOT forwarded upstream | The original threads `request.params._meta` into tools/list + tools/call. Ours drops it. **Known gap — P1 item** |
| 47 | Wire | `arguments` omitted when empty in tools/call | The original always sends `arguments: args || {}`. **Known gap — P1 item** |
| 48 | Wire | Failed-auth rate limiting (429 `too_many_requests` after 5 bad keys/15min) NOT implemented | The original has it. **Known gap — P1 item** |
| 49 | Wire | `serverInfo` = `{name:"submcp", version:"0.1.0"}` | The original advertises `metamcp-unified-<namespaceUuid>` / `1.0.0`. Undocumented in the original list — surfaced to users by MCP Inspector |
| 50 | Wire | `GET /mcp` + `POST /message` session-not-found → JSON body | The original sends plain text `"Session not found"` on those two paths (JSON only on POST /mcp). Ours is JSON everywhere |
| 51 | Wire | DELETE /mcp success → bare 200 (no body) | The original returns `{message, sessionId, remainingSessions}`. Ours is minimal |
| 52 | Wire | DELETE /mcp missing header → 400 `{error:"bad_request",...}` | The original returns `{error:"Missing sessionId", message:...}` |
| 53 | Wire | No Accept/Content-Type negotiation (406/415) and no JSON-RPC batch support | The SDK transport rejects non-conforming POSTs; ours accepts anything and treats batch arrays as parse errors |
| 54 | Wire | Body limit 16MB | The SDK's is 4MB (413 path) |
| 55 | Wire | Notifications 202'd BEFORE session validation | A notification on an expired/foreign session succeeds; the SDK validates session first. **Known gap — P1 item** |
| 56 | Wire | `writeJSONError` timestamps use RFC3339 (no ms) | Every other path uses `.000Z`; the original uses `toISOString()` (ms). Cosmetic |
| 57 | Wire | Endpoint-lookup DB error body: `{error:"internal_error", error_description:"Database error", timestamp}` | The original: `{error:"Internal server error", message:"Failed to lookup endpoint", timestamp}` |
| 58 | Wire | `GET /metamcp/health` + `/metamcp/health/sessions` absent (404 as unknown endpoint) | The original has both. **Known gap — P1 item** |
| 59 | Wire | Unsupported protocolVersion falls back to 2025-03-26 | The SDK 1.16 falls back to its LATEST (2025-06-18) and also supports 2024-10-07. Ours supports {2024-11-05, 2025-03-26, 2025-06-18} |
| 60 | Wire | `X-Forwarded-For` trusted unconditionally | A spoofed header defeats the rate limiter + admin allowlist. Deploy behind Traefik (which overwrites it). **Known gap — P1 item** |
| 61 | Wire | `unquarantine` issues a DB UPDATE on every successful list/call | See #43 |

## C. Known gaps (P1 items — NOT yet fixed, tracked)

1. `_meta` forwarding upstream (#46)
2. `arguments: {}` defaulting (#47)
3. Failed-auth rate limiter 429 (#48)
4. Notification-before-session-validation (#55)
5. `/metamcp/health` + `/metamcp/health/sessions` (#58)
6. X-Forwarded-For spoofing (#60)
7. `override_description` empty-string semantics: ours blanks the description; the original falls back to upstream (`|| null`) — verify and align
8. `annotations.title` stripping scope: ours strips only for MAPPED tools; the original applies to every tool whose server-name lookup resolves
9. Non-hint keys in `override_annotations` are dropped by ours; the original copies every key
10. The override-name sync filter is dead code: `buildRouteMap` warms the tool cache with `overrideNames=nil` before mappings load, so the later call hits cache

## D. How to update this file

Every intentional deviation must be: (1) implemented as described, (2)
covered by a golden test where wire-visible, (3) listed here. When a P1
gap is fixed, move it from C to A with a date. When a new deviation is
introduced, add it to B with a rationale. The golden suite is the
enforcement mechanism — if a test fails on a behavior listed here, the
test is wrong, not the behavior.
