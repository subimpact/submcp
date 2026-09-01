package mcp

import (
	"context"
	"sync"
	"time"
)

// Pool manages upstream connections per server UUID, with idle reuse and
// per-server caps. Mirrors mcp-server-pool.ts semantics:
//   - idle sessions keyed by server UUID (reused across downstream sessions)
//   - active sessions keyed by downstream sessionId -> serverUuid -> client
//   - maxTotalConnections and maxConnectionsPerServer caps
//   - 5-minute idle expiry sweep
type Pool struct {
	mu sync.Mutex

	maxTotal     int
	maxPerServer int
	idleTTL      time.Duration

	// idle[serverUUID] = stack of idle clients
	idle map[string][]*pooledClient
	// active[downstreamSessionID][serverUUID] = client
	active map[string]map[string]*pooledClient
	// lastUsed[serverUUID] = last time any idle client for this server was used
	lastUsed map[string]time.Time
}

type pooledClient struct {
	client *UpstreamClient
	usedAt time.Time
}

// NewPool creates a connection pool.
func NewPool(maxTotal, maxPerServer int, idleTTL time.Duration) *Pool {
	if maxTotal <= 0 {
		maxTotal = 100
	}
	if maxPerServer <= 0 {
		maxPerServer = 5
	}
	if idleTTL <= 0 {
		idleTTL = 5 * time.Minute
	}
	return &Pool{
		maxTotal:     maxTotal,
		maxPerServer: maxPerServer,
		idleTTL:      idleTTL,
		idle:         make(map[string][]*pooledClient),
		active:       make(map[string]map[string]*pooledClient),
		lastUsed:     make(map[string]time.Time),
	}
}

// Acquire returns a connected client for the given server, reusing an idle
// one if available, otherwise creating a new connection.
func (p *Pool) Acquire(ctx context.Context, sessionID, serverUUID string, factory func() (*UpstreamClient, error)) (*UpstreamClient, error) {
	p.mu.Lock()

	// Reuse idle if available.
	if stack := p.idle[serverUUID]; len(stack) > 0 {
		pc := stack[len(stack)-1]
		p.idle[serverUUID] = stack[:len(stack)-1]
		p.lastUsed[serverUUID] = time.Now()
		p.attachLocked(sessionID, serverUUID, pc)
		p.mu.Unlock()
		return pc.client, nil
	}

	// Check caps.
	totalActive := 0
	for _, m := range p.active {
		totalActive += len(m)
	}
	perServer := len(p.active[sessionID])
	if totalActive >= p.maxTotal {
		p.mu.Unlock()
		return nil, errPoolFull
	}
	if perServer >= p.maxPerServer {
		p.mu.Unlock()
		return nil, errPerServerFull
	}

	p.mu.Unlock()

	// Create new connection outside the lock.
	client, err := factory()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.attachLocked(sessionID, serverUUID, &pooledClient{client: client, usedAt: time.Now()})
	p.mu.Unlock()
	return client, nil
}

func (p *Pool) attachLocked(sessionID, serverUUID string, pc *pooledClient) {
	if p.active[sessionID] == nil {
		p.active[sessionID] = make(map[string]*pooledClient)
	}
	p.active[sessionID][serverUUID] = pc
}

// Release returns a client to the idle pool (or closes it if the pool is full).
func (p *Pool) Release(sessionID, serverUUID string) {
	p.mu.Lock()
	m := p.active[sessionID]
	if m == nil {
		p.mu.Unlock()
		return
	}
	pc, ok := m[serverUUID]
	if !ok {
		p.mu.Unlock()
		return
	}
	delete(m, serverUUID)
	if len(m) == 0 {
		delete(p.active, sessionID)
	}

	// Return to idle if under cap.
	if len(p.idle[serverUUID]) < p.maxPerServer {
		pc.usedAt = time.Now()
		p.idle[serverUUID] = append(p.idle[serverUUID], pc)
		p.lastUsed[serverUUID] = time.Now()
		p.mu.Unlock()
		return
	}

	p.mu.Unlock()
	// Pool full for this server — close the connection.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pc.client.Close(ctx)
}

// ReleaseSession releases all clients for a downstream session.
func (p *Pool) ReleaseSession(sessionID string) {
	p.mu.Lock()
	m := p.active[sessionID]
	if m == nil {
		p.mu.Unlock()
		return
	}
	delete(p.active, sessionID)
	var toClose []*UpstreamClient
	for _, pc := range m {
		if len(p.idle[pc.client.serverName]) < p.maxPerServer {
			pc.usedAt = time.Now()
			p.idle[pc.client.serverName] = append(p.idle[pc.client.serverName], pc)
		} else {
			toClose = append(toClose, pc.client)
		}
	}
	p.mu.Unlock()

	for _, c := range toClose {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c.Close(ctx)
		cancel()
	}
}

// SweepExpired closes idle connections older than the TTL.
func (p *Pool) SweepExpired() {
	p.mu.Lock()
	now := time.Now()
	var toClose []*UpstreamClient
	for serverUUID, stack := range p.idle {
		var kept []*pooledClient
		for _, pc := range stack {
			if now.Sub(pc.usedAt) > p.idleTTL {
				toClose = append(toClose, pc.client)
			} else {
				kept = append(kept, pc)
			}
		}
		p.idle[serverUUID] = kept
		if len(kept) == 0 {
			delete(p.idle, serverUUID)
			delete(p.lastUsed, serverUUID)
		}
	}
	p.mu.Unlock()

	for _, c := range toClose {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		c.Close(ctx)
		cancel()
	}
}

// Stats returns pool statistics for health/debug.
func (p *Pool) Stats() (idle, active int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, s := range p.idle {
		idle += len(s)
	}
	for _, m := range p.active {
		active += len(m)
	}
	return
}

var (
	errPoolFull      = &poolError{"connection pool full"}
	errPerServerFull = &poolError{"per-server connection limit reached"}
)

type poolError struct{ msg string }

func (e *poolError) Error() string { return e.msg }
