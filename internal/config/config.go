package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds all runtime configuration for submcp.
type Config struct {
	// HTTP
	ListenAddr string // e.g. ":12009" (backend port; fronted by Caddy/nginx)

	// Postgres
	PostgresHost     string
	PostgresPort     string
	PostgresUser     string
	PostgresPassword string
	PostgresDB       string
	PostgresSSLMode  string // disable | require | verify-full (default disable)

	// MCP behavior (config table defaults)
	MCPTimeout        time.Duration // default 60s
	MCPMaxAttempts    int           // default 1
	SessionLifetime   time.Duration // 0 = infinite
	MaxTotalConns     int           // default 100
	MaxConnsPerServer int           // default 20

	// Logging
	LogLevel string

	// P1-3: SSRF guard. Allow RFC1918/link-local upstreams (self-hosted
	// n8n etc.). 169.254/8 + 127.0.0.0/8 are ALWAYS blocked.
	AllowPrivateUpstreams bool

	// P2-3: admin allowlist mode. Comma-separated CIDRs/IPs; when set,
	// /api/admin/* is restricted to those source IPs (empty = allow all).
	AdminIPAllowlist string

	// SaaS (Phase 1): tenant subdomain base (e.g. ".mcp.subimpact.net").
	// When set, gateway requests are tenant-resolved by Host; when empty
	// the legacy single-tenant path (no tenant check) is used.
	TenantBaseHost string

	// SaaS: daily tool-call cap during trial (abuse protection). 0 = no cap.
	TrialDailyLimit int64

	// SaaS phase 4: tenant self-serve upstreams.
	// TenantAPIServiceToken authenticates the SaaS dashboard on the internal
	// listener (>= 32 chars, `openssl rand -hex 32`). Empty = listener off.
	TenantAPIServiceToken string
	// TenantAPIInternalAddr is the service-only listener. It is never published
	// to the host and Traefik has no route to it.
	TenantAPIInternalAddr string
	// TenantSecretKey seals tenant header values (AES-256-GCM). 32 bytes as
	// base64 (`openssl rand -base64 32`) or 64 hex characters.
	TenantSecretKey string
	// TenantMaxServers caps the upstream servers one tenant may register.
	TenantMaxServers int
	// TenantTestPerMinute caps test/refresh calls per tenant per minute.
	TenantTestPerMinute int
	// TenantPoolBudget caps the upstream connections in use for tenants together
	// (default 30% of MAX_TOTAL_CONNECTIONS), so operator acquires keep headroom.
	TenantPoolBudget int
	// TenantNamespaceInFlight caps the connections in use per tenant (its share
	// of the budget; default 3, SaaS 4c N2).
	TenantNamespaceInFlight int
	// TrustedProxyCIDRs lists the proxies whose X-Forwarded-For and
	// CF-Connecting-IP headers are believed (the Traefik network). Empty trusts
	// none, so the TCP peer is the client.
	TrustedProxyCIDRs string
}

// ValidateInternalAddr refuses a service listener that would bind every
// interface. The internal tenant API must bind the address of the internal
// docker network only (TENANT_API_INTERNAL_ADDR=<ip>:<port>), so a second
// network attached to the gateway cannot reach it.
func ValidateInternalAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("TENANT_API_INTERNAL_ADDR %q must be host:port", addr)
	}
	if port == "" {
		return fmt.Errorf("TENANT_API_INTERNAL_ADDR %q has no port", addr)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		return fmt.Errorf("TENANT_API_INTERNAL_ADDR %q binds every interface; bind the submcp-internal address (for example 10.77.0.10:12013)", addr)
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("TENANT_API_INTERNAL_ADDR %q must use an IP address", addr)
	}
	return nil
}

// Validate checks the whole configuration before any listener is bound (SaaS
// 4c, N6). Every problem is reported in one error, so a single restart shows
// them all. A value that is only read later (a bad key, a bad address) must
// fail here, not in a goroutine after the public listener is already serving.
func (c *Config) Validate() error {
	var errs []error
	if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
		errs = append(errs, fmt.Errorf("LISTEN_ADDR %q must be host:port", c.ListenAddr))
	}
	if err := ValidateCIDRList(c.TrustedProxyCIDRs); err != nil {
		errs = append(errs, err)
	}
	if c.TenantSecretKey != "" && !ValidSecretKey(c.TenantSecretKey) {
		errs = append(errs, errors.New("TENANT_SECRET_KEY must decode to exactly 32 bytes (openssl rand -base64 32)"))
	}
	if c.TenantBaseHost != "" && c.TenantSecretKey == "" {
		errs = append(errs, errors.New("TENANT_SECRET_KEY is required when TENANT_BASE_HOST is set (tenant API enabled)"))
	}
	if c.TenantAPIServiceToken != "" {
		if c.TenantBaseHost == "" {
			errs = append(errs, errors.New("TENANT_API_SERVICE_TOKEN needs TENANT_BASE_HOST (the tenant API is off without it)"))
		}
		if len(c.TenantAPIServiceToken) < 32 {
			errs = append(errs, errors.New("TENANT_API_SERVICE_TOKEN must be at least 32 characters (openssl rand -hex 32)"))
		}
		// The internal listener binds one address of submcp-internal. A missing
		// or wildcard address is refused here, before anything is bound.
		if err := ValidateInternalAddr(c.TenantAPIInternalAddr); err != nil {
			errs = append(errs, fmt.Errorf("internal tenant listener: %w (is submcp-internal attached with its address?)", err))
		}
	}
	for name, v := range map[string]int{
		"MAX_TOTAL_CONNECTIONS": c.MaxTotalConns, "MAX_CONNECTIONS_PER_SERVER": c.MaxConnsPerServer,
		"TENANT_MAX_SERVERS": c.TenantMaxServers, "TENANT_TEST_PER_MINUTE": c.TenantTestPerMinute,
		"TENANT_POOL_BUDGET": c.TenantPoolBudget, "TENANT_NS_IN_FLIGHT": c.TenantNamespaceInFlight,
	} {
		if v < 1 {
			errs = append(errs, fmt.Errorf("%s must be at least 1, got %d", name, v))
		}
	}
	return errors.Join(errs...)
}

// ValidateCIDRList accepts a comma-separated list of IPs and CIDRs (empty is
// valid and trusts nothing).
func ValidateCIDRList(list string) error {
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			if _, _, err := net.ParseCIDR(part); err != nil {
				return fmt.Errorf("TRUSTED_PROXY_CIDRS: %q is not a valid CIDR", part)
			}
			continue
		}
		if net.ParseIP(part) == nil {
			return fmt.Errorf("TRUSTED_PROXY_CIDRS: %q is not an IP or CIDR", part)
		}
	}
	return nil
}

// ValidSecretKey reports whether key is 32 bytes as standard base64 or 64 hex
// characters (the forms mcp.NewSecretBox accepts).
func ValidSecretKey(key string) bool {
	key = strings.TrimSpace(key)
	if b, err := base64.StdEncoding.DecodeString(key); err == nil && len(b) == 32 {
		return true
	}
	if h, err := hex.DecodeString(key); err == nil && len(h) == 32 {
		return true
	}
	return false
}

func Get() *Config {
	return &Config{
		ListenAddr:        getEnv("LISTEN_ADDR", ":12009"),
		PostgresHost:      getEnv("POSTGRES_HOST", "127.0.0.1"),
		PostgresPort:      getEnv("POSTGRES_PORT", "5432"),
		PostgresUser:      getEnv("POSTGRES_USER", "postgres"),
		PostgresPassword:  getEnv("POSTGRES_PASSWORD", ""),
		PostgresDB:        getEnv("POSTGRES_DB", "metamcp_db"),
		PostgresSSLMode:   getEnv("POSTGRES_SSLMODE", "disable"),
		MCPTimeout:        getEnvDur("MCP_TIMEOUT", 60*time.Second),
		MCPMaxAttempts:    getEnvInt("MCP_MAX_ATTEMPTS", 1),
		SessionLifetime:   getEnvDur("SESSION_LIFETIME", time.Hour),
		MaxTotalConns:     getEnvInt("MAX_TOTAL_CONNECTIONS", 100),
		MaxConnsPerServer: getEnvInt("MAX_CONNECTIONS_PER_SERVER", 20),
		LogLevel:          getEnv("LOG_LEVEL", "info"),
		// P1-3: default ON for self-hosted (n8n internal), OFF for SaaS.
		AllowPrivateUpstreams: getEnvBool("ALLOW_PRIVATE_UPSTREAMS", true),
		// P2-3: empty = allow all (default); set ADMIN_IP_ALLOWLIST to
		// restrict the admin plane (e.g. "10.0.0.0/8,203.0.113.5").
		AdminIPAllowlist: getEnv("ADMIN_IP_ALLOWLIST", ""),
		// SaaS tenant base host: "mcp.subimpact.net" means tenant slugs
		// resolve from "<slug>.mcp.subimpact.net". Empty = single-tenant.
		TenantBaseHost:  getEnv("TENANT_BASE_HOST", ""),
		TrialDailyLimit: getEnvInt64("TRIAL_DAILY_LIMIT", 0),

		TenantAPIServiceToken: getEnv("TENANT_API_SERVICE_TOKEN", ""),
		TenantAPIInternalAddr: getEnv("TENANT_API_INTERNAL_ADDR", ":12013"),
		// Unsafe defaults are refused by ValidateInternalAddr at startup.
		TenantSecretKey:         getEnv("TENANT_SECRET_KEY", ""),
		TenantMaxServers:        getEnvInt("TENANT_MAX_SERVERS", 10),
		TenantTestPerMinute:     getEnvInt("TENANT_TEST_PER_MINUTE", 10),
		TenantPoolBudget:        getEnvInt("TENANT_POOL_BUDGET", 30),
		TenantNamespaceInFlight: getEnvInt("TENANT_NS_IN_FLIGHT", 3),
		TrustedProxyCIDRs:       getEnv("TRUSTED_PROXY_CIDRS", ""),
	}
}

func getEnvInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func getEnvBool(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func getEnvDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
