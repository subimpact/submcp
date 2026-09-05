package mcp

import (
	"context"
	"sync"
	"time"
)

// Pool manages upstream connections per server UUID, with idle reuse and
// per-server caps. Mirrors mcp-server-pool.ts semantics:
//   - idle sessions keyed by server UUID (reused across downstream sessions)
//   - active sessions keyed by downstream sessionId -> serverUuid -> stack
//     (a stack, not a single slot, so concurrent tool calls to the same
//     upstream from one session each get their own connection)
//   - maxTotalConnections and maxConnectionsPerServer caps (per-server cap
//     is global across all sessions, not per-session)
//   - 5-minute idle expiry sweep
type Pool struct {
	mu sync.Mutex

	maxTotal     int
	maxPerServer int
	idleTTL      time.Duration

	// idle[serverUUID] = stack of idle clients
	idle map[string][]*pooledClient
	// active[downstreamSessionID][serverUUID] = stack of in-use clients
	active map[string]map[string][]*pooledClient
	// activePerServer[serverUUID] = total in-use connections to this server
	// across ALL sessions (the real per-server cap)
	activePerServer map[string]int
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
		maxTotal:        maxTotal,
		maxPerServer:    maxPerServer,
		idleTTL:         idleTTL,
		idle:            make(map[string][]*pooledClient),
		active:          make(map[string]map[string][]*pooledClient),
		activePerServer: make(map[string]int),
		lastUsed:        make(map[string]time.Time),
	}
}

// Acquire returns a connected client for the given server, reusing an idle
// one if available, otherwise creating a new connection. The per-server cap
// is reserved atomically BEFORE the factory runs (no check-then-act race),
// and rolled back if the factory fails.
func (p *Pool) Acquire(ctx context.Context, sessionID, serverUUID string, factory func() (*UpstreamClient, error)) (*UpstreamClient, error) {
	p.mu.Lock()

	// Reuse idle if available.
	if stack := p.idle[serverUUID]; len(stack) > 0 {
		pc := stack[len(stack)-1]
		p.idle[serverUUID] = stack[:len(stack)-1]
		p.lastUsed[serverUUID] = time.Now()
		p.attachLocked(sessionID, serverUUID, pc)
		p.activePerServer[serverUUID]++
		p.mu.Unlock()
		return pc.client, nil
	}

	// Check caps (global per-server count, not per-session).
	totalActive := 0
	for _, n := range p.activePerServer {
		totalActive += n
	}
	if totalActive >= p.maxTotal {
		p.mu.Unlock()
		return nil, errPoolFull
	}
	if p.activePerServer[serverUUID] >= p.maxPerServer {
		p.mu.Unlock()
		return nil, errPerServerFull
	}

	// Reserve the slot atomically while still holding the lock. The
	// factory runs outside the lock, but the reservation is held so N
	// concurrent acquires cannot all pass the cap check.
	p.activePerServer[serverUUID]++
	p.mu.Unlock()

	// Create new connection outside the lock.
	client, err := factory()
	if err != nil {
		// Roll back the reservation.
		p.mu.Lock()
		p.activePerServer[serverUUID]--
		if p.activePerServer[serverUUID] <= 0 {
			delete(p.activePerServer, serverUUID)
		}
		p.mu.Unlock()
		return nil, err
	}

	p.mu.Lock()
	p.attachLocked(sessionID, serverUUID, &pooledClient{client: client, usedAt: time.Now()})
	p.mu.Unlock()
	return client, nil
}

func (p *Pool) attachLocked(sessionID, serverUUID string, pc *pooledClient) {
	if p.active[sessionID] == nil {
		p.active[sessionID] = make(map[string][]*pooledClient)
	}
	p.active[sessionID][serverUUID] = append(p.active[sessionID][serverUUID], pc)
}

// Release returns a specific client to the idle pool (or closes it if the
// pool is full). The client is identified by pointer, NOT by LIFO pop: with
// concurrent acquires on the same (session, server), popping the top of the
// stack could hand an in-use connection to another caller (response
// cross-talk). Pointer identity is unambiguous because a client is always
// in exactly one place: idle stack or one session's active stack.
func (p *Pool) Release(sessionID, serverUUID string, client *UpstreamClient) {
	p.mu.Lock()
	m := p.active[sessionID]
	if m == nil {
		p.mu.Unlock()
		return
	}
	stack := m[serverUUID]
	idx := -1
	for i, pc := range stack {
		if pc.client == client {
			idx = i
			break
		}
	}
	if idx < 0 {
		// Not found: already released or never attached. Nothing to do.
		p.mu.Unlock()
		return
	}
	pc := stack[idx]
	// Remove by swap-with-last (order within the stack is irrelevant).
	stack[idx] = stack[len(stack)-1]
	stack = stack[:len(stack)-1]
	if len(stack) == 0 {
		delete(m, serverUUID)
	} else {
		m[serverUUID] = stack
	}
	if len(m) == 0 {
		delete(p.active, sessionID)
	}
	p.activePerServer[serverUUID]--

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
	for serverUUID, stack := range m {
		for _, pc := range stack {
			if len(p.idle[serverUUID]) < p.maxPerServer {
				pc.usedAt = time.Now()
				p.idle[serverUUID] = append(p.idle[serverUUID], pc)
				p.lastUsed[serverUUID] = time.Now()
			} else {
				toClose = append(toClose, pc.client)
			}
		}
		p.activePerServer[serverUUID] -= len(stack)
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
	for _, n := range p.activePerServer {
		active += n
	}
	return
}

var (
	errPoolFull      = &poolError{"connection pool full"}
	errPerServerFull = &poolError{"per-server connection limit reached"}
)

type poolError struct{ msg string }

func (e *poolError) Error() string { return e.msg }
