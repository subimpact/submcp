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
		SELECT uuid, name, key, user_id, created_at, is_active
		FROM api_keys WHERE key = $1 AND is_active = true`, key)
	var k APIKey
	err := row.Scan(&k.UUID, &k.Name, &k.Key, &k.UserID, &k.CreatedAt, &k.IsActive)
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
