package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/subimpact/submcp/internal/db"
)

// Boot-time migration of tenant credentials from the v1 AAD (header name only)
// to the v2 AAD (owner | server uuid | header). SQL cannot run AES-GCM, so this
// runs in Go after the schema migrations and before the listeners start. It is
// idempotent: a row already in v2 is left alone.

// LegacyHeaderStore is the DB surface the re-seal needs (*db.Pool implements it).
type LegacyHeaderStore interface {
	ListLegacyTenantHeaders(ctx context.Context) ([]db.TenantHeaderRow, error)
	SetTenantHeaders(ctx context.Context, serverUUID string, expected, headers json.RawMessage) error
}

// ResealLegacyTenantHeaders rewrites every v1 tenant header value to v2 and
// returns how many rows it rewrote. Any value that cannot be opened with the
// configured key stops the migration with an error: a wrong TENANT_SECRET_KEY
// must stop the boot rather than leave credentials silently unusable.
func ResealLegacyTenantHeaders(ctx context.Context, store LegacyHeaderStore, box *SecretBox) (int, error) {
	rows, err := store.ListLegacyTenantHeaders(ctx)
	if err != nil {
		return 0, fmt.Errorf("list legacy tenant credentials: %w", err)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	if box == nil {
		return 0, ErrNoSecretKey
	}
	done := 0
	for _, row := range rows {
		var stored map[string]string
		if err := json.Unmarshal(row.Headers, &stored); err != nil {
			return done, fmt.Errorf("server %s: stored headers are not a JSON object", row.ServerUUID)
		}
		out := make(map[string]string, len(stored))
		for name, v := range stored {
			switch {
			case strings.HasPrefix(v, sealPrefix):
				out[name] = v // already current; keep as is
			case strings.HasPrefix(v, legacySealPrefix):
				// v1 bound the header name only.
				plain, err := openWith(box, v[len(legacySealPrefix):], name)
				if err != nil {
					return done, fmt.Errorf("server %s header %s: legacy credential does not open with TENANT_SECRET_KEY", row.ServerUUID, name)
				}
				sealed, err := sealWith(box, sealPrefix, plain, tenantHeaderAAD(row.OwnerUserID, row.ServerUUID, name))
				if err != nil {
					return done, err
				}
				out[name] = sealed
			default:
				return done, fmt.Errorf("server %s header %s: a tenant credential is stored in plaintext; refusing to start", row.ServerUUID, name)
			}
		}
		raw, err := json.Marshal(out)
		if err != nil {
			return done, err
		}
		// Compare-and-set on the row as it was read: a concurrent write stops the
		// boot instead of being overwritten (SaaS 4c, N5).
		if err := store.SetTenantHeaders(ctx, row.ServerUUID, row.Headers, raw); err != nil {
			return done, fmt.Errorf("server %s: write re-sealed credentials: %w", row.ServerUUID, err)
		}
		done++
	}
	return done, nil
}
