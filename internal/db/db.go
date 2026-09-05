package db

import (
	"context"
	"embed"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Pool wraps the pgx connection pool.
type Pool struct {
	*pgxpool.Pool
}

// Connect establishes a Postgres connection pool.
func Connect(ctx context.Context, host, port, user, password, dbname string) (*Pool, error) {
	// Key/value DSN form (P1-13): avoids URL-encoding issues with special
	// characters in the password, and keeps the password out of a URL
	// string that could appear in error messages.
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable pool_max_conns=10",
		host, port, user, password, dbname)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse dsn: %w", err)
	}
	cfg.MaxConnLifetime = 30 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	// Verify connectivity with retry (postgres may still be starting).
	var pingErr error
	for i := 0; i < 10; i++ {
		pingCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		pingErr = pool.Ping(pingCtx)
		cancel()
		if pingErr == nil {
			return &Pool{pool}, nil
		}
		time.Sleep(2 * time.Second)
	}
	pool.Close()
	return nil, fmt.Errorf("ping postgres: %w", pingErr)
}

// Migrate applies pending SQL migrations from the embedded migrations dir.
// Each migration runs in its own transaction; a schema_migrations table
// records applied files so re-runs are no-ops. Migrations must be
// idempotent (IF NOT EXISTS / ON CONFLICT) as a belt-and-braces measure.
func (p *Pool) Migrate(ctx context.Context) error {
	_, err := p.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename text PRIMARY KEY,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`)
	if err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}

	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		var applied bool
		if err := p.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE filename = $1)`,
			e.Name()).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %s: %w", e.Name(), err)
		}
		if applied {
			continue
		}

		sqlBytes, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", e.Name(), err)
		}

		tx, err := p.Begin(ctx)
		if err != nil {
			return fmt.Errorf("begin migration %s: %w", e.Name(), err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply migration %s: %w", e.Name(), err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (filename) VALUES ($1)`, e.Name()); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("record migration %s: %w", e.Name(), err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("commit migration %s: %w", e.Name(), err)
		}
	}
	return nil
}
