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
