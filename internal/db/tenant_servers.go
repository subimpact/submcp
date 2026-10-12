package db

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Tenant-managed upstreams (SaaS phase 4). Every query is scoped by the
// owner's user_id AND tenant_managed = true. Rows with a NULL owner never match
// a caller id. Legacy rows (tenant_managed = false), including the operator's
// own rows, are invisible and unwritable here, even to the owner's keys: the
// operator's non-admin keys are bound to the operator user, and this stops them
// from converting an operator upstream into a tenant row.

// ErrTenantServerLimit means the tenant already has the maximum number of
// servers.
var ErrTenantServerLimit = errors.New("tenant server limit reached")

// ErrTenantNameTaken means the tenant already has a server with this name.
var ErrTenantNameTaken = errors.New("tenant server name already in use")

// TenantServerRow is one of a tenant's servers plus its discovered tool count.
type TenantServerRow struct {
	Server    MCPServer
	ToolCount int
}

// TenantHeaderRow is one tenant server's stored header JSON with its owner. The
// owner is part of the credential's associated data, so the re-seal needs it.
type TenantHeaderRow struct {
	ServerUUID  string
	OwnerUserID string
	Headers     json.RawMessage
}

// TenantToolRow is one discovered tool owned by a tenant, with its status in
// the tenant's endpoint namespace (ACTIVE when no mapping exists).
type TenantToolRow struct {
	ToolUUID    string
	ToolName    string // raw name, without the server prefix
	Description *string
	ServerUUID  string
	ServerName  string
	Status      ServerStatus
}

// isUniqueViolation reports a Postgres unique_violation (23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// TenantNamespaceUUID returns the namespace behind the tenant's "all"
// endpoint (the one every tenant endpoint URL serves), or "" when the tenant
// has not been provisioned.
func (p *Pool) TenantNamespaceUUID(ctx context.Context, userID string) (string, error) {
	var ns string
	err := p.QueryRow(ctx, `
		SELECT namespace_uuid::text FROM endpoints
		WHERE user_id = $1 AND name = 'all'`, userID).Scan(&ns)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return ns, err
}

// ListTenantServers returns the owner's servers, oldest first.
func (p *Pool) ListTenantServers(ctx context.Context, userID string) ([]TenantServerRow, error) {
	rows, err := p.Query(ctx, `
		SELECT s.uuid, s.name, s.description, s.type, s.command, s.args, s.env, s.url,
		       s.created_at, s.bearer_token, s.user_id, s.error_status, s.headers,
		       s.tenant_managed, s.last_error, s.last_checked_at,
		       (SELECT count(*) FROM tools t WHERE t.mcp_server_uuid = s.uuid)
		FROM mcp_servers s
		WHERE s.user_id = $1 AND s.tenant_managed = true
		ORDER BY s.created_at ASC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TenantServerRow
	for rows.Next() {
		var r TenantServerRow
		var count int64
		scan := func(dest ...any) error { return rows.Scan(append(dest, &count)...) }
		if err := scanServerRow(scan, &r.Server); err != nil {
			return nil, err
		}
		r.ToolCount = int(count)
		out = append(out, r)
	}
	return out, rows.Err()
}

// CreateTenantServer inserts a tenant-managed server and maps it into the
// tenant's namespace in one transaction. A per-tenant advisory lock makes the
// count check and the insert one decision, so concurrent creates cannot exceed
// maxServers. The caller may set s.UUID before the call (the credentials are
// sealed to it); otherwise the database generates one. On success s.UUID,
// s.CreatedAt and s.ErrorStatus are filled in.
func (p *Pool) CreateTenantServer(ctx context.Context, userID, nsUUID string, s *MCPServer, maxServers int) error {
	tx, err := p.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "tenant-servers:"+userID); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM mcp_servers WHERE user_id = $1 AND tenant_managed = true`, userID).Scan(&n); err != nil {
		return err
	}
	if n >= maxServers {
		return ErrTenantServerLimit
	}

	err = tx.QueryRow(ctx, `
		INSERT INTO mcp_servers (uuid, name, type, url, headers, user_id, tenant_managed)
		VALUES (COALESCE(NULLIF($6::text, '')::uuid, gen_random_uuid()), $1, $2, $3, $4, $5, true)
		RETURNING uuid::text, created_at, error_status`,
		s.Name, s.Type, s.URL, s.Headers, userID, s.UUID).Scan(&s.UUID, &s.CreatedAt, &s.ErrorStatus)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrTenantNameTaken
		}
		return err
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO namespace_server_mappings (namespace_uuid, mcp_server_uuid, status)
		VALUES ($1, $2, 'ACTIVE')`, nsUUID, s.UUID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.TenantManaged = true
	s.UserID = &userID
	return nil
}

// UpdateTenantServer rewrites a tenant server's editable fields. It clears the
// last check result and quarantine, since the upstream it describes changed.
// Returns false when the server does not belong to userID. The headers are
// written only while the row still holds expectedHeaders (compare-and-set): a
// PATCH that read the row before another write must not revert that write. A
// conflict returns ErrTenantHeadersChanged (SaaS 4c, N5).
func (p *Pool) UpdateTenantServer(ctx context.Context, userID string, s *MCPServer, expectedHeaders json.RawMessage) (bool, error) {
	if len(expectedHeaders) == 0 {
		expectedHeaders = json.RawMessage(`{}`)
	}
	tag, err := p.Exec(ctx, `
		UPDATE mcp_servers SET name = $3, type = $4, url = $5, headers = $6,
		       tenant_managed = true, error_status = 'NONE',
		       last_error = NULL, last_checked_at = NULL
		WHERE uuid = $1 AND user_id = $2 AND tenant_managed = true
		  AND headers IS NOT DISTINCT FROM $7`,
		s.UUID, userID, s.Name, s.Type, s.URL, s.Headers, expectedHeaders)
	if err != nil {
		if isUniqueViolation(err) {
			return false, ErrTenantNameTaken
		}
		return false, err
	}
	if tag.RowsAffected() > 0 {
		return true, nil
	}
	var owned bool
	if err := p.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM mcp_servers
		               WHERE uuid = $1 AND user_id = $2 AND tenant_managed = true)`,
		s.UUID, userID).Scan(&owned); err != nil {
		return false, err
	}
	if owned {
		return false, ErrTenantHeadersChanged
	}
	return false, nil
}

// DeleteTenantServer removes a tenant server; mappings and tools cascade.
// Returns false when the server does not belong to userID.
func (p *Pool) DeleteTenantServer(ctx context.Context, userID, serverUUID string) (bool, error) {
	tag, err := p.Exec(ctx, `DELETE FROM mcp_servers WHERE uuid = $1 AND user_id = $2 AND tenant_managed = true`, serverUUID, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// SetServerCheck records the outcome of the latest test or tools/list fetch.
// A nil lastError means the check succeeded. Only tenant-managed rows are
// written: an operator row never takes a tenant check result.
func (p *Pool) SetServerCheck(ctx context.Context, uuid string, lastError *string) error {
	_, err := p.Exec(ctx, `
		UPDATE mcp_servers SET last_error = $2, last_checked_at = now()
		WHERE uuid = $1 AND tenant_managed = true`, uuid, lastError)
	return err
}

// ListLegacyTenantHeaders returns the tenant rows whose headers still hold v1
// (header-name-only) ciphertext. Used once at boot by the re-seal.
func (p *Pool) ListLegacyTenantHeaders(ctx context.Context) ([]TenantHeaderRow, error) {
	rows, err := p.Query(ctx, `
		SELECT uuid::text, user_id, headers
		FROM mcp_servers
		WHERE tenant_managed = true AND user_id IS NOT NULL
		  AND headers::text LIKE '%enc:v1:%'
		ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TenantHeaderRow
	for rows.Next() {
		var r TenantHeaderRow
		if err := rows.Scan(&r.ServerUUID, &r.OwnerUserID, &r.Headers); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ErrTenantHeadersChanged means the stored headers differ from the value the
// writer read: another write landed first (a compare-and-set failed).
var ErrTenantHeadersChanged = errors.New("tenant server headers changed concurrently")

// SetTenantHeaders replaces the stored header JSON of one tenant row, only while
// the row still holds expected (compare-and-set, SaaS 4c N5). A conflict returns
// ErrTenantHeadersChanged; a missing tenant row returns ErrTenantServerNotFound.
func (p *Pool) SetTenantHeaders(ctx context.Context, serverUUID string, expected, headers json.RawMessage) error {
	if len(expected) == 0 {
		expected = json.RawMessage(`{}`)
	}
	tag, err := p.Exec(ctx, `
		UPDATE mcp_servers SET headers = $2
		WHERE uuid = $1 AND tenant_managed = true AND headers IS NOT DISTINCT FROM $3`,
		serverUUID, headers, expected)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}
	var exists bool
	if err := p.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM mcp_servers WHERE uuid = $1 AND tenant_managed = true)`,
		serverUUID).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrTenantHeadersChanged
	}
	return ErrTenantServerNotFound
}

// ErrTenantServerNotFound means no tenant-managed row has the given uuid.
var ErrTenantServerNotFound = errors.New("tenant server not found")

// ListTenantTools returns the owner's discovered tools with their status in
// nsUUID. An empty nsUUID means no mapping lookup (every tool reads ACTIVE).
func (p *Pool) ListTenantTools(ctx context.Context, userID, nsUUID string) ([]TenantToolRow, error) {
	var ns *string
	if nsUUID != "" {
		ns = &nsUUID
	}
	rows, err := p.Query(ctx, `
		SELECT t.uuid::text, t.name, t.description, s.uuid::text, s.name,
		       COALESCE(m.status::text, 'ACTIVE')
		FROM tools t
		JOIN mcp_servers s ON s.uuid = t.mcp_server_uuid
		LEFT JOIN namespace_tool_mappings m
		       ON m.tool_uuid = t.uuid AND m.namespace_uuid = $2::uuid
		WHERE s.user_id = $1 AND s.tenant_managed = true
		ORDER BY s.name, t.name`, userID, ns)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []TenantToolRow
	for rows.Next() {
		var r TenantToolRow
		var status string
		if err := rows.Scan(&r.ToolUUID, &r.ToolName, &r.Description, &r.ServerUUID, &r.ServerName, &status); err != nil {
			return nil, err
		}
		r.Status = ServerStatus(status)
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetTenantTool returns one tool owned by userID (nil when it is not theirs).
func (p *Pool) GetTenantTool(ctx context.Context, userID, toolUUID, nsUUID string) (*TenantToolRow, error) {
	var ns *string
	if nsUUID != "" {
		ns = &nsUUID
	}
	var r TenantToolRow
	var status string
	err := p.QueryRow(ctx, `
		SELECT t.uuid::text, t.name, t.description, s.uuid::text, s.name,
		       COALESCE(m.status::text, 'ACTIVE')
		FROM tools t
		JOIN mcp_servers s ON s.uuid = t.mcp_server_uuid
		LEFT JOIN namespace_tool_mappings m
		       ON m.tool_uuid = t.uuid AND m.namespace_uuid = $3::uuid
		WHERE s.user_id = $1 AND t.uuid = $2::uuid AND s.tenant_managed = true`, userID, toolUUID, ns).Scan(
		&r.ToolUUID, &r.ToolName, &r.Description, &r.ServerUUID, &r.ServerName, &status)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.Status = ServerStatus(status)
	return &r, nil
}

// SetToolMappingStatus enables (ACTIVE) or disables (INACTIVE) one tool in a
// namespace. The mapping row cascades away with the tool or the namespace.
func (p *Pool) SetToolMappingStatus(ctx context.Context, nsUUID, toolUUID, serverUUID string, status ServerStatus) error {
	_, err := p.Exec(ctx, `
		INSERT INTO namespace_tool_mappings (namespace_uuid, tool_uuid, mcp_server_uuid, status)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (namespace_uuid, tool_uuid) DO UPDATE SET status = EXCLUDED.status`,
		nsUUID, toolUUID, serverUUID, status)
	return err
}
