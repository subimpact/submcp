package main

import (
	"context"
	"errors"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/subimpact/submcp/internal/access"
	"github.com/subimpact/submcp/internal/config"
	"github.com/subimpact/submcp/internal/db"
	"github.com/subimpact/submcp/internal/httpapi"
	"github.com/subimpact/submcp/internal/mcp"
	"github.com/subimpact/submcp/internal/ui"
)

func main() {
	cfg := config.Get()
	// SaaS 4c (N6): all configuration is checked before anything is bound, so a
	// bad key, address or network stops the start with one readable error.
	if err := cfg.Validate(); err != nil {
		log.Fatalf("config: %v", err)
	}
	var secretBox *mcp.SecretBox
	if cfg.TenantSecretKey != "" {
		box, err := mcp.NewSecretBox(cfg.TenantSecretKey)
		if err != nil {
			log.Fatalf("TENANT_SECRET_KEY: %v", err)
		}
		secretBox = box
	}
	// The internal tenant listener binds its address on submcp-internal. It is
	// bound first, so a missing network stops the start before the database or
	// the public listener is touched.
	var internalLn net.Listener
	if cfg.TenantAPIServiceToken != "" && cfg.TenantBaseHost != "" {
		ln, err := net.Listen("tcp", cfg.TenantAPIInternalAddr)
		if err != nil {
			log.Fatalf("tenant API listener %s: %v (is submcp-internal attached with this address?)", cfg.TenantAPIInternalAddr, err)
		}
		internalLn = ln
	}

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

	// Trusted proxies (Traefik) decide which forwarded client address is believed.
	if err := mcp.SetTrustedProxies(cfg.TrustedProxyCIDRs); err != nil {
		log.Fatalf("%v", err)
	}
	// SaaS 4c (N1): tenant subdomains are DNS-only, so CF-Connecting-IP is ignored there.
	mcp.SetTenantBaseHost(cfg.TenantBaseHost)

	// Wire the gateway.
	pool := mcp.NewPool(cfg.MaxTotalConns, cfg.MaxConnsPerServer, 5*time.Minute)
	// SaaS phase 4b (#2): tenants share a budget of the pool and a per-tenant
	// in-flight cap, so operator acquires always have headroom.
	pool.SetTenantLimits(cfg.TenantPoolBudget, cfg.TenantNamespaceInFlight)
	// P1-3: SSRF guard — always block metadata/loopback; RFC1918 allowed
	// per ALLOW_PRIVATE_UPSTREAMS (default ON self-hosted).
	agg := mcp.NewAggregatorWithSSRF(pool, dbPool, mcp.NewSSRFGuard(cfg.AllowPrivateUpstreams))
	// SaaS Phase 4: tenant upstreams use the strict network policy (public
	// HTTPS only) and seal their credentials with TENANT_SECRET_KEY. The key was
	// checked before any listener was bound (see above).
	// SaaS phase 4b (#11): the gateway's own names are never tenant upstreams.
	agg.SetTenantUpstreams(secretBox, mcp.NewTenantNetPolicy(cfg.TenantBaseHost))
	// SaaS phase 4b (boot): tenant credentials sealed under the v1 AAD are
	// re-sealed to v2 before anything serves. A key that cannot open them stops
	// the boot.
	if secretBox != nil {
		n, err := mcp.ResealLegacyTenantHeaders(ctx, dbPool, secretBox)
		if err != nil {
			log.Fatalf("tenant credential re-seal: %v", err)
		}
		if n > 0 {
			log.Printf("re-sealed %d tenant server credential row(s) to the v2 AAD", n)
		}
	}
	auth := mcp.NewAuth(dbPool)
	srv := mcp.NewServer(dbPool, agg, pool, auth, cfg.SessionLifetime)
	// SaaS Phase 1: tenant entitlement + trial usage cap. Enabled only when
	// a tenant base host is configured; the legacy single-tenant deployment
	// (no TENANT_BASE_HOST) keeps working untouched.
	if cfg.TenantBaseHost != "" {
		// SaaS phase 4b (P1 secrets): tenant mode always seals credentials, so a
		// missing key stops the boot instead of failing each tenant request.
		if cfg.TenantSecretKey == "" {
			log.Fatalf("TENANT_SECRET_KEY is required when TENANT_BASE_HOST is set (tenant API enabled)")
		}
		srv.EnableTenants(dbPool, cfg.TenantBaseHost, cfg.TrialDailyLimit)
		// SaaS Phase 4: tenant self-serve upstreams (public API with X-API-Key).
		if err := srv.EnableTenantAPI(dbPool, mcp.TenantAPIConfig{
			ServiceToken:  cfg.TenantAPIServiceToken,
			MaxServers:    cfg.TenantMaxServers,
			TestPerMinute: cfg.TenantTestPerMinute,
		}); err != nil {
			log.Fatalf("tenant api: %v", err)
		}
	}

	// Admin UI (embedded, mounted at /). P2-3: optional admin IP
	// allowlist via ADMIN_IP_ALLOWLIST (empty = allow all).
	//
	// R3: admin login via a verified Cloudflare Access JWT. All three
	// required settings (ACCESS_TEAM_DOMAIN, ACCESS_AUD, ADMIN_EMAILS) must
	// be present; anything missing leaves JWT login off and the API-key
	// login as the only admin login. No deployment values are logged here:
	// the team domain and aud tag stay in the env file.
	var accessVerifier *access.Verifier
	if cfg.Access.Ready() {
		accessVerifier = access.New(cfg.Access)
		logger.Info("admin Cloudflare Access login enabled")
	} else {
		logger.Info("admin Cloudflare Access login disabled")
	}
	adminUI := ui.NewWithAccess(dbPool, cfg.AdminIPAllowlist, accessVerifier)

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
		ReadTimeout: 30 * time.Second,
		IdleTimeout: 120 * time.Second,
	}
	// SaaS 4c (N6): listeners are bound here, and serve errors come back on
	// serveErr. Nothing calls Fatalf from a goroutine.
	publicLn, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("listen %s: %v", cfg.ListenAddr, err)
	}
	serveErr := make(chan error, 2)
	go func() {
		log.Printf("submcp listening on %s", cfg.ListenAddr)
		serveErr <- httpServer.Serve(publicLn)
	}()

	// SaaS Phase 4: service-only listener for the SaaS dashboard. It starts only
	// with a service token, and it is never published to the host (see
	// httpapi.BuildInternal and scripts/deploy-blue-green.sh).
	var internalServer *http.Server
	if internalLn != nil {
		internalServer = &http.Server{
			Addr:              cfg.TenantAPIInternalAddr,
			Handler:           httpapi.BuildInternal(logger, srv),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			log.Printf("tenant API (service auth) listening on %s", cfg.TenantAPIInternalAddr)
			serveErr <- internalServer.Serve(internalLn)
		}()
	}

	// Graceful shutdown. A listener that stops serving unexpectedly ends the
	// process with a non-zero status, so the orchestrator restarts it.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	var exitErr error
	select {
	case <-stop:
	case err := <-serveErr:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			exitErr = err
		}
	}
	log.Println("shutting down...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpServer.Shutdown(shutdownCtx)
	if internalServer != nil {
		_ = internalServer.Shutdown(shutdownCtx)
	}
	if exitErr != nil {
		log.Fatalf("listener stopped: %v", exitErr)
	}
}
