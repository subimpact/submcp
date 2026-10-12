package mcp

import (
	"context"
	"fmt"
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
//
// Tenant-managed upstreams (SaaS phase 4) also draw on two budgets that the
// operator path never waits on (see AcquireTenant):
//   - a tenant budget: at most tenantBudget connections in use for tenants
//     together, so tenant traffic can never take the whole pool;
//   - a per-tenant in-flight cap: at most tenantPerKey concurrent acquires per
//     tenant. Acquires past the cap wait, bounded by the caller's context.
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
	// across ALL sessions (the real per-server cap). Zero entries are deleted,
	// so the map holds only servers with something in use (SaaS 4c, N3).
	activePerServer map[string]int
	// activeTotal is the sum of activePerServer, kept as a running total so the
	// pool cap check is O(1) rather than a scan of every server on each acquire.
	activeTotal int
	// lastUsed[serverUUID] = last time any idle client for this server was used
	lastUsed map[string]time.Time

	// Tenant budgets. tenantActive counts in-use tenant connections; the
	// per-tenant semaphores bound concurrent tenant acquires per tenant key.
	tenantBudget int
	tenantPerKey int
	tenantActive int
	tenantSem    map[string]chan struct{}
}

type pooledClient struct {
	client *UpstreamClient
	usedAt time.Time
	// tenant is set while the client is checked out by a tenant acquire; it
	// holds the budget and the tenant's slot until Release.
	tenant    bool
	tenantKey string
}

// Default tenant budget: 30% of the total pool, and at most 3 connections in
// use per tenant (SaaS 4c, N2). Eight tenants that each hold their share use 24
// of the 30, so a ninth tenant still gets a slot. Operator headroom is the
// remaining 70% (at the default total of 100).
const (
	tenantBudgetPercent = 30
	tenantDefaultPerKey = 3
)

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
	budget := maxTotal * tenantBudgetPercent / 100
	if budget < 1 {
		budget = 1
	}
	return &Pool{
		maxTotal:        maxTotal,
		maxPerServer:    maxPerServer,
		idleTTL:         idleTTL,
		idle:            make(map[string][]*pooledClient),
		active:          make(map[string]map[string][]*pooledClient),
		activePerServer: make(map[string]int),
		lastUsed:        make(map[string]time.Time),
		tenantBudget:    budget,
		tenantPerKey:    tenantDefaultPerKey,
		tenantSem:       make(map[string]chan struct{}),
	}
}

// SetTenantLimits overrides the tenant budget (connections across all tenants)
// and the per-tenant in-flight cap. Call once at startup. Values below 1 are
// ignored. The budget is capped at the total pool size.
func (p *Pool) SetTenantLimits(budget, perKey int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if budget >= 1 {
		if budget > p.maxTotal {
			budget = p.maxTotal
		}
		p.tenantBudget = budget
	}
	if perKey >= 1 {
		p.tenantPerKey = perKey
	}
}

// Acquire returns a connected client for the given operator server, reusing an
// idle one if available, otherwise creating a new connection. The per-server cap
// is reserved atomically BEFORE the factory runs (no check-then-act race), and
// rolled back if the factory fails. Operator acquires never wait on tenant
// budgets: the tenant budget leaves them headroom.
func (p *Pool) Acquire(ctx context.Context, sessionID, serverUUID string, factory func() (*UpstreamClient, error)) (*UpstreamClient, error) {
	return p.acquire(ctx, sessionID, serverUUID, factory, false, "")
}

// AcquireTenant returns a connected client for a tenant-managed server. It
// takes one slot of the tenant's in-flight cap (waiting for one, bounded by
// ctx) and one unit of the tenant budget (failing fast with errTenantBudgetFull
// when the budget is spent). tenantKey identifies the tenant; it is the owner's
// user id, since each tenant has one namespace and pooled connections are
// shared across namespaces.
func (p *Pool) AcquireTenant(ctx context.Context, sessionID, serverUUID, tenantKey string, factory func() (*UpstreamClient, error)) (*UpstreamClient, error) {
	sem := p.tenantSemFor(tenantKey)
	select {
	case sem <- struct{}{}:
	case <-ctx.Done():
		return nil, fmt.Errorf("tenant upstream busy: %w", ctx.Err())
	}

	// SaaS 4c (N8): the budget unit and the in-flight slot are returned on every
	// exit that does not hand a client out, including a panic in the factory.
	granted := false
	defer func() {
		if !granted {
			<-sem
		}
	}()

	p.mu.Lock()
	if p.tenantActive >= p.tenantBudget {
		p.mu.Unlock()
		return nil, errTenantBudgetFull
	}
	p.tenantActive++
	p.mu.Unlock()
	defer func() {
		if !granted {
			p.mu.Lock()
			p.tenantActive--
			p.mu.Unlock()
		}
	}()

	client, err := p.acquire(ctx, sessionID, serverUUID, factory, true, tenantKey)
	if err != nil {
		return nil, err
	}
	granted = true
	return client, nil
}

// tenantSemFor returns the in-flight semaphore for a tenant key. Semaphores are
// created once and never removed, so two acquires can never hold two different
// semaphores for the same tenant.
func (p *Pool) tenantSemFor(tenantKey string) chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	sem, ok := p.tenantSem[tenantKey]
	if !ok {
		sem = make(chan struct{}, p.tenantPerKey)
		p.tenantSem[tenantKey] = sem
	}
	return sem
}

func (p *Pool) acquire(ctx context.Context, sessionID, serverUUID string, factory func() (*UpstreamClient, error), tenant bool, tenantKey string) (*UpstreamClient, error) {
	p.mu.Lock()

	// Reuse idle if available.
	if stack := p.idle[serverUUID]; len(stack) > 0 {
		pc := stack[len(stack)-1]
		p.idle[serverUUID] = stack[:len(stack)-1]
		p.lastUsed[serverUUID] = time.Now()
		pc.tenant = tenant
		pc.tenantKey = tenantKey
		p.attachLocked(sessionID, serverUUID, pc)
		p.incActiveLocked(serverUUID)
		p.mu.Unlock()
		return pc.client, nil
	}

	// Check caps (global per-server count, not per-session).
	if p.activeTotal >= p.maxTotal {
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
	p.incActiveLocked(serverUUID)
	p.mu.Unlock()

	// Any exit that does not hand a client out (an error, or a panic in the
	// factory) returns the reservation (SaaS 4c, N8).
	handedOut := false
	defer func() {
		if !handedOut {
			p.mu.Lock()
			p.decActiveLocked(serverUUID, 1)
			p.mu.Unlock()
		}
	}()

	// Create new connection outside the lock.
	client, err := factory()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.attachLocked(sessionID, serverUUID, &pooledClient{client: client, usedAt: time.Now(), tenant: tenant, tenantKey: tenantKey})
	p.mu.Unlock()
	handedOut = true
	return client, nil
}

// incActiveLocked reserves one in-use connection for a server. The caller holds p.mu.
func (p *Pool) incActiveLocked(serverUUID string) {
	p.activePerServer[serverUUID]++
	p.activeTotal++
}

// decActiveLocked returns n in-use connections for a server, deleting the entry
// once it reaches zero so the map does not grow with every server ever used.
// The caller holds p.mu.
func (p *Pool) decActiveLocked(serverUUID string, n int) {
	cur := p.activePerServer[serverUUID]
	if n > cur {
		n = cur
	}
	if n <= 0 {
		return
	}
	if cur == n {
		delete(p.activePerServer, serverUUID)
	} else {
		p.activePerServer[serverUUID] = cur - n
	}
	p.activeTotal -= n
}

func (p *Pool) attachLocked(sessionID, serverUUID string, pc *pooledClient) {
	if p.active[sessionID] == nil {
		p.active[sessionID] = make(map[string][]*pooledClient)
	}
	p.active[sessionID][serverUUID] = append(p.active[sessionID][serverUUID], pc)
}

// releaseTenantLocked returns a tenant client's budget unit and in-flight slot.
// The caller holds p.mu. The slot token is always present: it was taken when
// the client was attached.
func (p *Pool) releaseTenantLocked(pc *pooledClient) {
	if !pc.tenant {
		return
	}
	pc.tenant = false
	p.tenantActive--
	<-p.tenantSem[pc.tenantKey]
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
	p.decActiveLocked(serverUUID, 1)
	p.releaseTenantLocked(pc)

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
			p.releaseTenantLocked(pc)
			if len(p.idle[serverUUID]) < p.maxPerServer {
				pc.usedAt = time.Now()
				p.idle[serverUUID] = append(p.idle[serverUUID], pc)
				p.lastUsed[serverUUID] = time.Now()
			} else {
				toClose = append(toClose, pc.client)
			}
		}
		p.decActiveLocked(serverUUID, len(stack))
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
	return idle, p.activeTotal
}

// TenantStats returns the tenant budget in use and its size.
func (p *Pool) TenantStats() (inUse, budget int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.tenantActive, p.tenantBudget
}

var (
	errPoolFull         = &poolError{"connection pool full"}
	errPerServerFull    = &poolError{"per-server connection limit reached"}
	errTenantBudgetFull = &poolError{"tenant upstream capacity is full; retry shortly"}
)

type poolError struct{ msg string }

func (e *poolError) Error() string { return e.msg }
