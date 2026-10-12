# submcp

A lightweight MCP (Model Context Protocol) gateway that aggregates multiple upstream MCP servers into a single unified endpoint.

- **Single binary** — ~15 MB static Go binary, no Node.js runtime, no `node_modules`
- **Multi-upstream fan-out** — one `tools/list` / `tools/call` fans out to every registered server
- **Namespaced tools** — tools are prefixed `server__tool` (e.g. `peecai__list_projects`, `tavily-1__tavily_search`)
- **Streamable HTTP + legacy SSE** — both transports served from the same process
- **API-key auth** — `X-API-Key` header, `Authorization: Bearer`, or query param
- **Postgres-backed** — endpoints, namespaces, servers, tool mappings, and API keys live in Postgres
- **Failure isolation** — a dead upstream is skipped; the rest still respond

## Quick start

```bash
# Build
go build -o bin/submcp ./cmd/submcp

# Run (env-driven config)
POSTGRES_HOST=127.0.0.1 \
POSTGRES_PORT=5432 \
POSTGRES_USER=postgres \
POSTGRES_PASSWORD=secret \
POSTGRES_DB=metamcp_db \
LISTEN_ADDR=:12009 \
./bin/submcp
```

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/metamcp/:endpoint/mcp` | POST | Streamable HTTP (initialize, tools/list, tools/call) |
| `/metamcp/:endpoint/mcp` | GET | SSE stream for an existing session |
| `/metamcp/:endpoint/mcp` | DELETE | Terminate a session |
| `/metamcp/:endpoint/sse` | GET | Legacy SSE transport |
| `/metamcp/:endpoint/message` | POST | SSE message endpoint |
| `/health` | GET | Health check |
| `/api/tenant/servers` (and `/{id}`, `/{id}/test`, `/{id}/refresh`, `/tools`) | GET, POST, PATCH, DELETE | Tenant self-serve upstreams. `X-API-Key` (tenant key) on the public listener |

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `LISTEN_ADDR` | `:12009` | HTTP listen address |
| `POSTGRES_HOST` | `127.0.0.1` | Postgres host |
| `POSTGRES_PORT` | `5432` | Postgres port |
| `POSTGRES_USER` | `postgres` | Postgres user |
| `POSTGRES_PASSWORD` | — | Postgres password |
| `POSTGRES_DB` | `metamcp_db` | Postgres database |
| `MCP_TIMEOUT` | `60s` | Upstream request timeout |
| `MCP_MAX_ATTEMPTS` | `1` | Upstream connect attempts |
| `MAX_TOTAL_CONNECTIONS` | `100` | Upstream connection pool cap |
| `MAX_CONNECTIONS_PER_SERVER` | `5` | Per-server pool cap |
| `LOG_LEVEL` | `info` | Log level |
| `TENANT_BASE_HOST` | none | Tenant subdomain base (for example `mcp.example.com`). Enables tenant mode |
| `TENANT_API_SERVICE_TOKEN` | none | Shared secret for the internal tenant API listener (32+ characters). Unset disables the listener |
| `TENANT_API_INTERNAL_ADDR` | `:12013` | Service-only listener. Never publish it to the host or a router |
| `TENANT_SECRET_KEY` | none | 32-byte key (base64 or 64 hex) that seals tenant credentials at rest (AES-256-GCM). Losing it loses those credentials |
| `TENANT_MAX_SERVERS` | `10` | Upstream servers per tenant |
| `TENANT_TEST_PER_MINUTE` | `10` | Test/refresh calls per tenant per minute |
| `TENANT_POOL_BUDGET` | `30` | Tenant connections in use across all tenants (30% of the pool) |
| `TENANT_NS_IN_FLIGHT` | `3` | Connections in use per tenant (its share of the budget) |
| `TRUSTED_PROXY_CIDRS` | none | Proxies whose `CF-Connecting-IP` and `X-Forwarded-For` are believed. The deploy script sets Traefik's exact address |

Startup validates the whole configuration before any listener is bound
(`config.Validate`). A bad key, address, CIDR list or missing network stops the
process with one error that lists every problem.

## Tenant upstreams

Tenants register their own remote MCP servers through the tenant API. Each
server joins the tenant's `all` endpoint without a restart. Rules that apply
to tenant servers (operator servers are unchanged):

- Streamable HTTP or SSE only. STDIO is refused, since it would run a command on the host.
- `https://` hostnames on port 443 only. IP literals, single-label names, and
  `localhost`-style names are refused. No credentials or query strings in the URL.
- Every name is resolved and every address is checked against the private,
  loopback, link-local, CGNAT, metadata and reserved ranges. The connection is
  dialed only to checked addresses, so DNS rebinding does not help. Redirects
  are not followed.
- Header values are sealed at rest and shown masked (last four characters).
- Test and refresh are rate limited per tenant. Inactive tenants can read and
  remove servers but not add, change or test them.

## Database migrations

Migrations are the embedded `internal/db/migrations/*.sql` files, applied in
name order, one transaction each. Every new migration starts with a lock
timeout, so a migration that cannot get its lock fails in seconds instead of
queueing behind live traffic (SaaS 4c, N14):

```sql
-- NNNN_short_description.sql
-- What this changes and why. Idempotent where the statement allows it.
SET LOCAL lock_timeout = '5s';

-- the change itself
```

Use `SET LOCAL`: each migration runs in its own transaction, so the setting ends
at commit. A plain `SET` would stay on the pooled connection and change the lock
timeout of the next query that reuses it. Migration 0006 predates this rule and
is not changed.

## Database

The schema is plain Postgres (16 tables). The gateway reads:

- `endpoints` — public endpoint names → namespace mapping
- `namespaces` — namespace definitions
- `mcp_servers` — upstream server configs (type, url, bearer token, headers)
- `namespace_server_mappings` — which servers belong to which namespace
- `namespace_tool_mappings` — per-tool filtering and overrides
- `tools` — cached tool definitions
- `api_keys` — API keys for auth

## Docker

```bash
docker build -t submcp .
docker run -d --name submcp \
  -e POSTGRES_HOST=host.docker.internal \
  -e POSTGRES_PASSWORD=secret \
  -p 12009:12009 \
  submcp
```

## License

MIT
