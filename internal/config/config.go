package config

import (
	"os"
	"strconv"
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
	MCPTimeout       time.Duration // default 60s
	MCPMaxAttempts   int           // default 1
	SessionLifetime  time.Duration // 0 = infinite
	MaxTotalConns    int           // default 100
	MaxConnsPerServer int          // default 5

	// Logging
	LogLevel string

	// P1-3: SSRF guard. Allow RFC1918/link-local upstreams (self-hosted
	// n8n etc.). 169.254/8 + 127.0.0.0/8 are ALWAYS blocked.
	AllowPrivateUpstreams bool

	// P2-3: admin allowlist mode. Comma-separated CIDRs/IPs; when set,
	// /api/admin/* is restricted to those source IPs (empty = allow all).
	AdminIPAllowlist string
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
	}
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
