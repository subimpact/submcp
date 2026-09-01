package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Pool wraps the pgx connection pool.
type Pool struct {
	*pgxpool.Pool
}

// Connect establishes a Postgres connection pool.
func Connect(ctx context.Context, host, port, user, password, dbname string) (*Pool, error) {
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable&pool_max_conns=10",
		user, password, host, port, dbname,
	)
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
