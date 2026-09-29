package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"expvar"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Metrics exposes runtime counters via expvar at /metrics (P1-6).
// Per-upstream counters: calls, failures, breaker state. Pool gauges are
// read live from the Pool on each scrape.
type Metrics struct {
	mu       sync.Mutex
	upstream map[string]*upstreamMetrics
	pool     *Pool
	start    time.Time
}

type upstreamMetrics struct {
	calls    *expvar.Int
	failures *expvar.Int
	state    *expvar.String
}

var metricsRegistry = expvar.NewMap("submcp")

// NewMetrics creates the metrics collector.
func NewMetrics(pool *Pool) *Metrics {
	m := &Metrics{
		upstream: make(map[string]*upstreamMetrics),
		pool:     pool,
		start:    time.Now(),
	}
	metricsRegistry.Set("uptime_seconds", expvar.Func(func() any {
		return int64(time.Since(m.start).Seconds())
	}))
	metricsRegistry.Set("pool", expvar.Func(func() any {
		if m.pool == nil {
			return map[string]any{}
		}
		idle, active := m.pool.Stats()
		return map[string]any{"idle": idle, "active": active}
	}))
	return m
}

// RecordCall increments the call counter for an upstream.
// Fix 5 (P0): expvar keys use a HASH of the server UUID and never expose
// the server name - /metrics is unauthenticated and leaked every tenant's
// server UUIDs + names. The uuid/name mapping lives in the admin UI only.
func (m *Metrics) RecordCall(serverUUID, serverName string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	um := m.upstream[serverUUID]
	if um == nil {
		um = &upstreamMetrics{
			calls:    new(expvar.Int),
			failures: new(expvar.Int),
			state:    new(expvar.String),
		}
		m.upstream[serverUUID] = um
		sum := sha256.Sum256([]byte(serverUUID))
		metricsKey := "upstream_" + hex.EncodeToString(sum[:6])
		metricsRegistry.Set(metricsKey, expvar.Func(func() any {
			return map[string]any{
				"calls":    um.calls.Value(),
				"failures": um.failures.Value(),
				"state":    um.state.Value(),
			}
		}))
	}
	um.calls.Add(1)
}

// RecordFailure increments the failure counter and updates breaker state.
func (m *Metrics) RecordFailure(serverUUID, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if um := m.upstream[serverUUID]; um != nil {
		um.failures.Add(1)
		um.state.Set(state)
	}
}

// RecordState updates the breaker state for an upstream.
func (m *Metrics) RecordState(serverUUID, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if um := m.upstream[serverUUID]; um != nil {
		um.state.Set(state)
	}
}

// Handler serves the expvar metrics (P1-6 /metrics).
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		fmt.Fprintf(w, "{\n")
		first := true
		metricsRegistry.Do(func(kv expvar.KeyValue) {
			if !first {
				fmt.Fprintf(w, ",\n")
			}
			first = false
			fmt.Fprintf(w, "%q: %s", kv.Key, kv.Value)
		})
		fmt.Fprintf(w, "\n}\n")
	})
}
