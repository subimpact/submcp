package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/subimpact/submcp/internal/config"
	"github.com/subimpact/submcp/internal/db"
	"github.com/subimpact/submcp/internal/httpapi"
	"github.com/subimpact/submcp/internal/mcp"
	"github.com/subimpact/submcp/internal/ui"
)

func main() {
	cfg := config.Get()

	// Structured logging (P1-14): slog with level from config.
	var level slog.Level
	switch cfg.LogLevel {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to Postgres (the same DB the gateway has always used).
	dbPool, err := db.Connect(ctx, cfg.PostgresHost, cfg.PostgresPort,
		cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresDB, cfg.PostgresSSLMode)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer dbPool.Close()
	log.Printf("connected to postgres %s:%s/%s", cfg.PostgresHost, cfg.PostgresPort, cfg.PostgresDB)

	// Apply pending schema migrations (idempotent, embedded).
	if err := dbPool.Migrate(ctx); err != nil {
		log.Fatalf("migrate: %v", err)
	}
	log.Printf("migrations applied")

	// Wire the gateway.
	pool := mcp.NewPool(cfg.MaxTotalConns, cfg.MaxConnsPerServer, 5*time.Minute)
	// P1-3: SSRF guard — always block metadata/loopback; RFC1918 allowed
	// per ALLOW_PRIVATE_UPSTREAMS (default ON self-hosted).
	agg := mcp.NewAggregatorWithSSRF(pool, dbPool, mcp.NewSSRFGuard(cfg.AllowPrivateUpstreams))
	auth := mcp.NewAuth(dbPool)
	srv := mcp.NewServer(dbPool, agg, pool, auth, cfg.SessionLifetime)

	// Admin UI (embedded, mounted at /). P2-3: optional admin IP
	// allowlist via ADMIN_IP_ALLOWLIST (empty = allow all).
	adminUI := ui.NewWithAllowlist(dbPool, cfg.AdminIPAllowlist)

	// Root handler: gateway routes + admin UI, wrapped in request
	// logging (P1-14). Assembled in internal/httpapi so tests drive the
	// same chain the deployed binary serves.
	handler := httpapi.Build(logger, srv, adminUI)

	// Idle sweep + session TTL sweep (P1-4).
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			pool.SweepExpired()
			for _, sid := range srv.SweepSessions() {
				pool.ReleaseSession(sid)
			}
			adminUI.SweepSessions()
		}
	}()

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// P2-7: ReadTimeout bounds slow-loris body reads; IdleTimeout
		// reaps idle keep-alive conns. WriteTimeout is deliberately NOT
		// set — SSE streams (streamable GET, legacy /sse) are long-lived
		// and a write deadline would kill them mid-stream.
		ReadTimeout:  30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("submcp listening on %s", cfg.ListenAddr)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	// Graceful shutdown.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
}
