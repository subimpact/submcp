package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// TenantStatus mirrors the tenants.status lifecycle.
type TenantStatus string

const (
	TenantTrialing TenantStatus = "trialing"
	TenantActive   TenantStatus = "active"
	TenantPastDue  TenantStatus = "past_due"
	TenantCanceled TenantStatus = "canceled"
)

// Tenant is a row from tenants.
type Tenant struct {
	ID                    string       `json:"id"`
	UserID                string       `json:"user_id"`
	Slug                  string       `json:"slug"`
	Status                TenantStatus `json:"status"`
	TrialEndsAt           *time.Time   `json:"trial_ends_at"`
	StripeCustomerID      *string      `json:"stripe_customer_id"`
	StripeSubscriptionID  *string      `json:"stripe_subscription_id"`
	Plan                  string       `json:"plan"`
	SubscriptionEndsAt    *time.Time   `json:"subscription_ends_at"`
	CanceledAt            *time.Time   `json:"canceled_at"`
	CreatedAt             time.Time    `json:"created_at"`
	UpdatedAt             time.Time    `json:"updated_at"`
}

// GetTenantByID returns a tenant row by UUID.
func (p *Pool) GetTenantByID(ctx context.Context, id string) (*Tenant, error) {
	row := p.QueryRow(ctx, `
		SELECT id, user_id, slug, status, trial_ends_at, stripe_customer_id,
		       stripe_subscription_id, plan, subscription_ends_at, canceled_at,
		       created_at, updated_at
		FROM tenants WHERE id = $1`, id)
	var t Tenant
	err := row.Scan(&t.ID, &t.UserID, &t.Slug, &t.Status, &t.TrialEndsAt,
		&t.StripeCustomerID, &t.StripeSubscriptionID, &t.Plan, &t.SubscriptionEndsAt,
		&t.CanceledAt, &t.CreatedAt, &t.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// GetTenantByUserID returns a tenant row by the linked user id.
func (p *Pool) GetTenantByUserID(ctx context.Context, userID string) (*Tenant, error) {
	row := p.QueryRow(ctx, `
		SELECT id, user_id, slug, status, trial_ends_at, stripe_customer_id,
		       stripe_subscription_id, plan, subscription_ends_at, canceled_at,
		       created_at, updated_at
		FROM tenants WHERE user_id = $1`, userID)
	var t Tenant
	err := row.Scan(&t.ID, &t.UserID, &t.Slug, &t.Status, &t.TrialEndsAt,
		&t.StripeCustomerID, &t.StripeSubscriptionID, &t.Plan, &t.SubscriptionEndsAt,
		&t.CanceledAt, &t.CreatedAt, &t.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// GetTenantBySlug returns a tenant row by subdomain slug.
func (p *Pool) GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error) {
	row := p.QueryRow(ctx, `
		SELECT id, user_id, slug, status, trial_ends_at, stripe_customer_id,
		       stripe_subscription_id, plan, subscription_ends_at, canceled_at,
		       created_at, updated_at
		FROM tenants WHERE slug = $1`, slug)
	var t Tenant
	err := row.Scan(&t.ID, &t.UserID, &t.Slug, &t.Status, &t.TrialEndsAt,
		&t.StripeCustomerID, &t.StripeSubscriptionID, &t.Plan, &t.SubscriptionEndsAt,
		&t.CanceledAt, &t.CreatedAt, &t.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// TenantEntitlement is the computed access decision for a tenant.
// Denied=false means the gateway must reject (trial over / canceled / past-due).
type TenantEntitlement struct {
	Tenant   *Tenant
	Denied   bool
	Reason   string
	// TrialEnded reports that a trialing tenant is past trial_ends_at but
	// not yet canceled (Stripe webhook may lag by seconds).
	TrialEnded bool
}

// Entitlement computes whether a tenant may use the gateway right now.
//   - trialing: allowed until trial_ends_at (usage cap still applies)
//   - active  : allowed (subscription current)
//   - past_due: allowed for PAYMENT_GRACE (default 7d), then denied
//   - canceled: denied (data grace 30d for re-subscribe, gateway off)
func (p *Pool) Entitlement(ctx context.Context, t *Tenant) (*TenantEntitlement, error) {
	now := time.Now()
	e := &TenantEntitlement{Tenant: t}
	switch t.Status {
	case TenantTrialing:
		if t.TrialEndsAt != nil && now.After(*t.TrialEndsAt) {
			e.Denied = true
			e.TrialEnded = true
			e.Reason = "trial_ended"
		}
	case TenantActive:
		// subscription current — allowed.
	case TenantPastDue:
		if t.SubscriptionEndsAt == nil || now.Sub(*t.SubscriptionEndsAt) > 7*24*time.Hour {
			e.Denied = true
			e.Reason = "payment_overdue"
		}
	case TenantCanceled:
		e.Denied = true
		e.Reason = "subscription_canceled"
	default:
		e.Denied = true
		e.Reason = "unknown_tenant_status"
	}
	return e, nil
}

// BumpUsage increments the tenant's daily tool-call counter (usage cap).
// Upsert on (tenant_id, day) so counters survive across calls.
func (p *Pool) BumpUsage(ctx context.Context, tenantID string) error {
	_, err := p.Exec(ctx, `
		INSERT INTO usage_daily (tenant_id, day, calls) VALUES ($1, current_date, 1)
		ON CONFLICT (tenant_id, day) DO UPDATE SET calls = usage_daily.calls + 1`,
		tenantID)
	return err
}

// UsageToday returns the tenant's tool-call count for today (0 = none).
func (p *Pool) UsageToday(ctx context.Context, tenantID string) (int64, error) {
	var n int64
	err := p.QueryRow(ctx, `
		SELECT calls FROM usage_daily WHERE tenant_id = $1 AND day = current_date`,
		tenantID).Scan(&n)
	if err == pgx.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return n, nil
}

// --- provisioning (used by the SaaS control plane) ---

// ProvisionTenant creates the full tenant row for a user in one step.
// The SaaS service calls this after creating the user (auth layer owns
// users/sessions; this owns tenants). Idempotent on user_id and slug.
func (p *Pool) ProvisionTenant(ctx context.Context, userID, slug string, trialDays int) (*Tenant, error) {
	trialEnd := time.Now().Add(time.Duration(trialDays) * 24 * time.Hour)
	row := p.QueryRow(ctx, `
		INSERT INTO tenants (user_id, slug, status, trial_ends_at)
		VALUES ($1, $2, 'trialing', $3)
		ON CONFLICT (user_id) DO UPDATE SET slug = EXCLUDED.slug, updated_at = now()
		RETURNING id, user_id, slug, status, trial_ends_at, stripe_customer_id,
		          stripe_subscription_id, plan, subscription_ends_at, canceled_at,
		          created_at, updated_at`,
		userID, slug, trialEnd)
	var t Tenant
	err := row.Scan(&t.ID, &t.UserID, &t.Slug, &t.Status, &t.TrialEndsAt,
		&t.StripeCustomerID, &t.StripeSubscriptionID, &t.Plan, &t.SubscriptionEndsAt,
		&t.CanceledAt, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// SetTenantSubscription links a Stripe subscription to a tenant (webhook path).
func (p *Pool) SetTenantSubscription(ctx context.Context, tenantID, customerID, subscriptionID string, status TenantStatus, periodEnd *time.Time) error {
	_, err := p.Exec(ctx, `
		UPDATE tenants SET stripe_customer_id = $2, stripe_subscription_id = $3,
		       status = $4, subscription_ends_at = $5, updated_at = now()
		WHERE id = $1`,
		tenantID, customerID, subscriptionID, status, periodEnd)
	return err
}

// SetTenantStatus flips a tenant's status (webhook / reconcile path).
func (p *Pool) SetTenantStatus(ctx context.Context, tenantID string, status TenantStatus) error {
	_, err := p.Exec(ctx, `
		UPDATE tenants SET status = $2, updated_at = now() WHERE id = $1`,
		tenantID, status)
	return err
}

// CancelTenant marks a tenant canceled (customer.subscription.deleted).
// Data is kept (30-day grace) — the gateway denies until reactivation.
func (p *Pool) CancelTenant(ctx context.Context, tenantID string) error {
	_, err := p.Exec(ctx, `
		UPDATE tenants SET status = 'canceled', canceled_at = now(), updated_at = now()
		WHERE id = $1`, tenantID)
	return err
}

// RecordStripeEvent logs a webhook event id for idempotency.
// Returns false when the event was already seen (caller skips processing).
func (p *Pool) RecordStripeEvent(ctx context.Context, eventID, eventType string) (bool, error) {
	tag, err := p.Exec(ctx, `
		INSERT INTO stripe_events (event_id, type) VALUES ($1, $2)
		ON CONFLICT (event_id) DO NOTHING`, eventID, eventType)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
