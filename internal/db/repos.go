package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// ServerType mirrors the mcp_server_type enum.
type ServerType string

const (
	ServerTypeStdio          ServerType = "STDIO"
	ServerTypeSSE            ServerType = "SSE"
	ServerTypeStreamableHTTP ServerType = "STREAMABLE_HTTP"
)

// ServerStatus mirrors the mcp_server_status enum.
type ServerStatus string

const (
	ServerStatusActive   ServerStatus = "ACTIVE"
	ServerStatusInactive ServerStatus = "INACTIVE"
)

// ErrorStatus mirrors the mcp_server_error_status enum.
type ErrorStatus string

const (
	ErrorStatusNone ErrorStatus = "NONE"
	ErrorStatusErr  ErrorStatus = "ERROR"
)

// MCPServer is a row from mcp_servers.
type MCPServer struct {
	UUID        string          `json:"uuid"`
	Name        string          `json:"name"`
	Description *string         `json:"description"`
	Type        ServerType      `json:"type"`
	Command     *string         `json:"command"`
	Args        []string        `json:"args"`
	Env         json.RawMessage `json:"env"`
	URL         *string         `json:"url"`
	CreatedAt   time.Time       `json:"created_at"`
	BearerToken *string         `json:"bearer_token"`
	UserID      *string         `json:"user_id"`
	ErrorStatus ErrorStatus     `json:"error_status"`
	Headers     json.RawMessage `json:"headers"`
}

// Endpoint is a row from endpoints.
type Endpoint struct {
	UUID              string    `json:"uuid"`
	Name              string    `json:"name"`
	Description       *string   `json:"description"`
	NamespaceUUID     string    `json:"namespace_uuid"`
	EnableAPIKeyAuth  bool      `json:"enable_api_key_auth"`
	UseQueryParamAuth bool      `json:"use_query_param_auth"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
	UserID            *string   `json:"user_id"`
	EnableOAuth       bool      `json:"enable_oauth"`
}

// Namespace is a row from namespaces.
type Namespace struct {
	UUID        string    `json:"uuid"`
	Name        string    `json:"name"`
	Description *string   `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	UserID      *string   `json:"user_id"`
}

// NamespaceServerMapping is a row from namespace_server_mappings.
type NamespaceServerMapping struct {
	UUID          string       `json:"uuid"`
	NamespaceUUID string       `json:"namespace_uuid"`
	MCPServerUUID string       `json:"mcp_server_uuid"`
	Status        ServerStatus `json:"status"`
	CreatedAt     time.Time    `json:"created_at"`
}

// Tool is a row from tools.
type Tool struct {
	UUID         string          `json:"uuid"`
	Name         string          `json:"name"`
	Description  *string         `json:"description"`
	ToolSchema   json.RawMessage `json:"tool_schema"`
	CreatedAt    time.Time       `json:"created_at"`
	UpdatedAt    time.Time       `json:"updated_at"`
	MCPServerUUID string         `json:"mcp_server_uuid"`
}

// NamespaceToolMapping is a row from namespace_tool_mappings.
type NamespaceToolMapping struct {
	UUID          string          `json:"uuid"`
	NamespaceUUID string          `json:"namespace_uuid"`
	ToolUUID      string          `json:"tool_uuid"`
	MCPServerUUID string          `json:"mcp_server_uuid"`
	Status        ServerStatus    `json:"status"`
	CreatedAt     time.Time       `json:"created_at"`
	OverrideName  *string         `json:"override_name"`
	OverrideDesc  *string         `json:"override_description"`
	OverrideTitle *string         `json:"override_title"`
	OverrideAnn   json.RawMessage `json:"override_annotations"`
}

// APIKey is a row from api_keys.
type APIKey struct {
	UUID      string    `json:"uuid"`
	Name      string    `json:"name"`
	Key       string    `json:"key"`
	UserID    *string   `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	IsActive  bool      `json:"is_active"`
	IsAdmin   bool      `json:"is_admin"`
}

// GetEndpointByName looks up an endpoint by its public name.
func (p *Pool) GetEndpointByName(ctx context.Context, name string) (*Endpoint, error) {
	row := p.QueryRow(ctx, `
		SELECT uuid, name, description, namespace_uuid, enable_api_key_auth,
		       use_query_param_auth, created_at, updated_at, user_id, enable_oauth
		FROM endpoints WHERE name = $1`, name)
	var e Endpoint
	err := row.Scan(&e.UUID, &e.Name, &e.Description, &e.NamespaceUUID,
		&e.EnableAPIKeyAuth, &e.UseQueryParamAuth, &e.CreatedAt, &e.UpdatedAt,
		&e.UserID, &e.EnableOAuth)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &e, nil
}

// GetNamespace returns a namespace by UUID.
func (p *Pool) GetNamespace(ctx context.Context, uuid string) (*Namespace, error) {
	row := p.QueryRow(ctx, `
		SELECT uuid, name, description, created_at, updated_at, user_id
		FROM namespaces WHERE uuid = $1`, uuid)
	var n Namespace
	err := row.Scan(&n.UUID, &n.Name, &n.Description, &n.CreatedAt, &n.UpdatedAt, &n.UserID)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// GetActiveServersForNamespace returns ACTIVE, non-quarantined servers
// mapped to a namespace. Filters ACTIVE and error_status = NONE.
func (p *Pool) GetActiveServersForNamespace(ctx context.Context, namespaceUUID string) ([]MCPServer, error) {
	rows, err := p.Query(ctx, `
		SELECT s.uuid, s.name, s.description, s.type, s.command, s.args, s.env,
		       s.url, s.created_at, s.bearer_token, s.user_id, s.error_status, s.headers
		FROM mcp_servers s
		JOIN namespace_server_mappings m ON m.mcp_server_uuid = s.uuid
		WHERE m.namespace_uuid = $1
		  AND m.status = 'ACTIVE'
		  AND s.error_status = 'NONE'
		ORDER BY s.created_at ASC`, namespaceUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var servers []MCPServer
	for rows.Next() {
		var s MCPServer
		if err := rows.Scan(&s.UUID, &s.Name, &s.Description, &s.Type, &s.Command,
			&s.Args, &s.Env, &s.URL, &s.CreatedAt, &s.BearerToken, &s.UserID,
			&s.ErrorStatus, &s.Headers); err != nil {
			return nil, err
		}
		servers = append(servers, s)
	}
	return servers, rows.Err()
}

// GetToolMappings returns tool mappings for a namespace, joined with tool
// details. Used for filtering and overrides.
func (p *Pool) GetToolMappings(ctx context.Context, namespaceUUID string) ([]struct {
	Mapping NamespaceToolMapping
	Tool    Tool
}, error) {
	rows, err := p.Query(ctx, `
		SELECT tm.uuid, tm.namespace_uuid, tm.tool_uuid, tm.mcp_server_uuid,
		       tm.status, tm.created_at, tm.override_name, tm.override_description,
		       tm.override_title, tm.override_annotations,
		       t.uuid, t.name, t.description, t.tool_schema, t.created_at, t.updated_at, t.mcp_server_uuid
		FROM namespace_tool_mappings tm
		JOIN tools t ON t.uuid = tm.tool_uuid
		WHERE tm.namespace_uuid = $1`, namespaceUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []struct {
		Mapping NamespaceToolMapping
		Tool    Tool
	}
	for rows.Next() {
		var item struct {
			Mapping NamespaceToolMapping
			Tool    Tool
		}
		if err := rows.Scan(
			&item.Mapping.UUID, &item.Mapping.NamespaceUUID, &item.Mapping.ToolUUID,
			&item.Mapping.MCPServerUUID, &item.Mapping.Status, &item.Mapping.CreatedAt,
			&item.Mapping.OverrideName, &item.Mapping.OverrideDesc, &item.Mapping.OverrideTitle,
			&item.Mapping.OverrideAnn,
			&item.Tool.UUID, &item.Tool.Name, &item.Tool.Description, &item.Tool.ToolSchema,
			&item.Tool.CreatedAt, &item.Tool.UpdatedAt, &item.Tool.MCPServerUUID,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// ValidateAPIKey checks a key against api_keys. Mirrors api-keys.repo.ts
// validation (eq on key, is_active).
func (p *Pool) ValidateAPIKey(ctx context.Context, key string) (*APIKey, error) {
	row := p.QueryRow(ctx, `
		SELECT uuid, name, key, user_id, created_at, is_active, is_admin
		FROM api_keys WHERE key = $1 AND is_active = true`, key)
	var k APIKey
	err := row.Scan(&k.UUID, &k.Name, &k.Key, &k.UserID, &k.CreatedAt, &k.IsActive, &k.IsAdmin)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// ListEndpoints returns all endpoints (used by the unauthenticated
// enumeration route — kept for parity, see roadmap S4).
func (p *Pool) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	rows, err := p.Query(ctx, `
		SELECT uuid, name, description, namespace_uuid, enable_api_key_auth,
		       use_query_param_auth, created_at, updated_at, user_id, enable_oauth
		FROM endpoints ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Endpoint
	for rows.Next() {
		var e Endpoint
		if err := rows.Scan(&e.UUID, &e.Name, &e.Description, &e.NamespaceUUID,
			&e.EnableAPIKeyAuth, &e.UseQueryParamAuth, &e.CreatedAt, &e.UpdatedAt,
			&e.UserID, &e.EnableOAuth); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountTools returns the total number of cached tool definitions.
func (p *Pool) CountTools(ctx context.Context) (int, error) {
	var n int
	err := p.QueryRow(ctx, `SELECT count(*) FROM tools`).Scan(&n)
	return n, err
}

// CountNamespaces returns the number of namespaces.
func (p *Pool) CountNamespaces(ctx context.Context) (int, error) {
	var n int
	err := p.QueryRow(ctx, `SELECT count(*) FROM namespaces`).Scan(&n)
	return n, err
}

// --- Admin UI repo methods ---

// ListServers returns all MCP servers (admin view).
func (p *Pool) ListServers(ctx context.Context) ([]MCPServer, error) {
	rows, err := p.Query(ctx, `
		SELECT uuid, name, description, type, command, args, env, url,
		       created_at, bearer_token, user_id, error_status, headers
		FROM mcp_servers ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []MCPServer
	for rows.Next() {
		var s MCPServer
		if err := rows.Scan(&s.UUID, &s.Name, &s.Description, &s.Type, &s.Command,
			&s.Args, &s.Env, &s.URL, &s.CreatedAt, &s.BearerToken, &s.UserID,
			&s.ErrorStatus, &s.Headers); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// GetServer returns one server by UUID.
func (p *Pool) GetServer(ctx context.Context, uuid string) (*MCPServer, error) {
	row := p.QueryRow(ctx, `
		SELECT uuid, name, description, type, command, args, env, url,
		       created_at, bearer_token, user_id, error_status, headers
		FROM mcp_servers WHERE uuid = $1`, uuid)
	var s MCPServer
	err := row.Scan(&s.UUID, &s.Name, &s.Description, &s.Type, &s.Command,
		&s.Args, &s.Env, &s.URL, &s.CreatedAt, &s.BearerToken, &s.UserID,
		&s.ErrorStatus, &s.Headers)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// CreateServer inserts a new MCP server.
func (p *Pool) CreateServer(ctx context.Context, s *MCPServer) error {
	return p.QueryRow(ctx, `
		INSERT INTO mcp_servers (name, description, type, command, args, env, url,
		                         bearer_token, headers)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING uuid, created_at`,
		s.Name, s.Description, s.Type, s.Command, s.Args, s.Env, s.URL,
		s.BearerToken, s.Headers).Scan(&s.UUID, &s.CreatedAt)
}

// UpdateServer updates editable fields of a server.
func (p *Pool) UpdateServer(ctx context.Context, s *MCPServer) error {
	_, err := p.Exec(ctx, `
		UPDATE mcp_servers SET name = $2, description = $3, type = $4,
		       command = $5, args = $6, env = $7, url = $8, bearer_token = $9,
		       headers = $10
		WHERE uuid = $1`,
		s.UUID, s.Name, s.Description, s.Type, s.Command, s.Args, s.Env,
		s.URL, s.BearerToken, s.Headers)
	return err
}

// DeleteServer removes a server and its mappings (cascade handles tools).
func (p *Pool) DeleteServer(ctx context.Context, uuid string) error {
	_, err := p.Exec(ctx, `DELETE FROM mcp_servers WHERE uuid = $1`, uuid)
	return err
}

// ListNamespaces returns all namespaces.
func (p *Pool) ListNamespaces(ctx context.Context) ([]Namespace, error) {
	rows, err := p.Query(ctx, `
		SELECT uuid, name, description, created_at, updated_at, user_id
		FROM namespaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Namespace
	for rows.Next() {
		var n Namespace
		if err := rows.Scan(&n.UUID, &n.Name, &n.Description, &n.CreatedAt,
			&n.UpdatedAt, &n.UserID); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// CreateNamespace inserts a new namespace.
func (p *Pool) CreateNamespace(ctx context.Context, n *Namespace) error {
	return p.QueryRow(ctx, `
		INSERT INTO namespaces (name, description)
		VALUES ($1, $2) RETURNING uuid, created_at, updated_at`,
		n.Name, n.Description).Scan(&n.UUID, &n.CreatedAt, &n.UpdatedAt)
}

// DeleteNamespace removes a namespace (cascade removes mappings/endpoints).
func (p *Pool) DeleteNamespace(ctx context.Context, uuid string) error {
	_, err := p.Exec(ctx, `DELETE FROM namespaces WHERE uuid = $1`, uuid)
	return err
}

// ListNamespaceServerMappings returns server mappings for a namespace.
func (p *Pool) ListNamespaceServerMappings(ctx context.Context, namespaceUUID string) ([]NamespaceServerMapping, error) {
	rows, err := p.Query(ctx, `
		SELECT uuid, namespace_uuid, mcp_server_uuid, status, created_at
		FROM namespace_server_mappings WHERE namespace_uuid = $1`, namespaceUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []NamespaceServerMapping
	for rows.Next() {
		var m NamespaceServerMapping
		if err := rows.Scan(&m.UUID, &m.NamespaceUUID, &m.MCPServerUUID,
			&m.Status, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetServerMapping upserts a server's status in a namespace.
func (p *Pool) SetServerMapping(ctx context.Context, namespaceUUID, serverUUID string, status ServerStatus) error {
	_, err := p.Exec(ctx, `
		INSERT INTO namespace_server_mappings (namespace_uuid, mcp_server_uuid, status)
		VALUES ($1, $2, $3)
		ON CONFLICT (namespace_uuid, mcp_server_uuid)
		DO UPDATE SET status = EXCLUDED.status`,
		namespaceUUID, serverUUID, status)
	return err
}

// ListAPIKeys returns all API keys (admin view, key values included).
func (p *Pool) ListAPIKeys(ctx context.Context) ([]APIKey, error) {
	rows, err := p.Query(ctx, `
		SELECT uuid, name, key, user_id, created_at, is_active, is_admin
		FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.UUID, &k.Name, &k.Key, &k.UserID, &k.CreatedAt,
			&k.IsActive, &k.IsAdmin); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// CreateAPIKey inserts a new API key.
func (p *Pool) CreateAPIKey(ctx context.Context, name, key string, isAdmin bool) (*APIKey, error) {
	var k APIKey
	err := p.QueryRow(ctx, `
		INSERT INTO api_keys (name, key, is_admin)
		VALUES ($1, $2, $3) RETURNING uuid, created_at, is_active, is_admin`,
		name, key, isAdmin).Scan(&k.UUID, &k.CreatedAt, &k.IsActive, &k.IsAdmin)
	if err != nil {
		return nil, err
	}
	k.Name = name
	k.Key = key
	return &k, nil
}

// SetAPIKeyActive toggles an API key's active state.
func (p *Pool) SetAPIKeyActive(ctx context.Context, uuid string, active bool) error {
	_, err := p.Exec(ctx, `UPDATE api_keys SET is_active = $2 WHERE uuid = $1`, uuid, active)
	return err
}

// ListToolsByServer returns tools for a server.
func (p *Pool) ListToolsByServer(ctx context.Context, serverUUID string) ([]Tool, error) {
	rows, err := p.Query(ctx, `
		SELECT uuid, name, description, tool_schema, created_at, updated_at, mcp_server_uuid
		FROM tools WHERE mcp_server_uuid = $1 ORDER BY name`, serverUUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Tool
	for rows.Next() {
		var t Tool
		if err := rows.Scan(&t.UUID, &t.Name, &t.Description, &t.ToolSchema,
			&t.CreatedAt, &t.UpdatedAt, &t.MCPServerUUID); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// CreateEndpoint inserts a new endpoint.
func (p *Pool) CreateEndpoint(ctx context.Context, e *Endpoint) error {
	return p.QueryRow(ctx, `
		INSERT INTO endpoints (name, description, namespace_uuid, enable_api_key_auth,
		                       use_query_param_auth, enable_oauth)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING uuid, created_at, updated_at`,
		e.Name, e.Description, e.NamespaceUUID, e.EnableAPIKeyAuth,
		e.UseQueryParamAuth, e.EnableOAuth).Scan(&e.UUID, &e.CreatedAt, &e.UpdatedAt)
}

// UpdateEndpoint updates an endpoint.
func (p *Pool) UpdateEndpoint(ctx context.Context, e *Endpoint) error {
	_, err := p.Exec(ctx, `
		UPDATE endpoints SET name = $2, description = $3, namespace_uuid = $4,
		       enable_api_key_auth = $5, use_query_param_auth = $6, enable_oauth = $7,
		       updated_at = now()
		WHERE uuid = $1`,
		e.UUID, e.Name, e.Description, e.NamespaceUUID, e.EnableAPIKeyAuth,
		e.UseQueryParamAuth, e.EnableOAuth)
	return err
}

// DeleteEndpoint removes an endpoint.
func (p *Pool) DeleteEndpoint(ctx context.Context, uuid string) error {
	_, err := p.Exec(ctx, `DELETE FROM endpoints WHERE uuid = $1`, uuid)
	return err
}
