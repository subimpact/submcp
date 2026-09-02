package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/subimpact/submcp/internal/config"
	"github.com/subimpact/submcp/internal/db"
	"github.com/subimpact/submcp/internal/mcp"
	"github.com/subimpact/submcp/internal/ui"
)

func main() {
	cfg := config.Get()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to Postgres (the same DB the gateway has always used).
	dbPool, err := db.Connect(ctx, cfg.PostgresHost, cfg.PostgresPort,
		cfg.PostgresUser, cfg.PostgresPassword, cfg.PostgresDB)
	if err != nil {
		log.Fatalf("postgres: %v", err)
	}
	defer dbPool.Close()
	log.Printf("connected to postgres %s:%s/%s", cfg.PostgresHost, cfg.PostgresPort, cfg.PostgresDB)

	// Wire the gateway.
	pool := mcp.NewPool(cfg.MaxTotalConns, cfg.MaxConnsPerServer, 5*time.Minute)
	agg := mcp.NewAggregator(pool, dbPool)
	auth := mcp.NewAuth(dbPool)
	srv := mcp.NewServer(dbPool, agg, pool, auth)

	// Admin UI (embedded, mounted at /).
	adminUI := ui.New(dbPool)

	// Root handler: gateway routes + admin UI.
	root := http.NewServeMux()
	root.Handle("/", adminUI.Handler())
	root.Handle("/health", srv.Handler())
	root.Handle("/metamcp/", srv.Handler())

	// Idle sweep.
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			pool.SweepExpired()
		}
	}()

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
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
