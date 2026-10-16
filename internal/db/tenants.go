package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// TenantStatus mirrors the tenants.status lifecycle.
type TenantStatus string

const (
	TenantTrialing   TenantStatus = "trialing"
	TenantActive     TenantStatus = "active"
	TenantPastDue    TenantStatus = "past_due"
	TenantUnpaid     TenantStatus = "unpaid"
	TenantIncomplete TenantStatus = "incomplete"
	TenantPaused     TenantStatus = "paused"
	TenantCanceled   TenantStatus = "canceled"
	// TenantPendingVerification: the account exists but its email address is
	// not confirmed yet. No trial clock runs and the gateway denies access.
	TenantPendingVerification TenantStatus = "pending_verification"
)

// PastDueGrace is how long a past_due tenant keeps access, counted from
// past_due_since (the moment the tenant became past_due). Stripe moves
// current_period_end forward at each renewal, so it cannot anchor the grace.
const PastDueGrace = 3 * 24 * time.Hour

// Tenant is a row from tenants. Billing state is written by the SaaS webhook;
// the gateway only reads it.
type Tenant struct {
	ID                   string       `json:"id"`
	UserID               string       `json:"user_id"`
	Slug                 string       `json:"slug"`
	Status               TenantStatus `json:"status"`
	TrialEndsAt          *time.Time   `json:"trial_ends_at"`
	StripeCustomerID     *string      `json:"stripe_customer_id"`
	StripeSubscriptionID *string      `json:"stripe_subscription_id"`
	Plan                 string       `json:"plan"`
	SubscriptionEndsAt   *time.Time   `json:"subscription_ends_at"`
	CanceledAt           *time.Time   `json:"canceled_at"`
	PastDueSince         *time.Time   `json:"past_due_since"`
	// SuspendedAt is operator-set suspension state (migration 0008), kept out
	// of status so Stripe webhooks rewriting status cannot lift it.
	SuspendedAt     *time.Time `json:"suspended_at"`
	SuspendedReason *string    `json:"suspended_reason"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// tenantCols lists the tenants columns read by scanTenant, in order.
const tenantCols = `id, user_id, slug, status, trial_ends_at, stripe_customer_id,
	stripe_subscription_id, plan, subscription_ends_at, canceled_at,
	past_due_since, suspended_at, suspended_reason, created_at, updated_at`

func scanTenant(scan func(dest ...any) error, t *Tenant) error {
	return scan(&t.ID, &t.UserID, &t.Slug, &t.Status, &t.TrialEndsAt,
		&t.StripeCustomerID, &t.StripeSubscriptionID, &t.Plan, &t.SubscriptionEndsAt,
		&t.CanceledAt, &t.PastDueSince, &t.SuspendedAt, &t.SuspendedReason,
		&t.CreatedAt, &t.UpdatedAt)
}

// GetTenantByID returns a tenant row by UUID.
func (p *Pool) GetTenantByID(ctx context.Context, id string) (*Tenant, error) {
	var t Tenant
	err := scanTenant(p.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE id = $1`, id).Scan, &t)
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
	var t Tenant
	err := scanTenant(p.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE user_id = $1`, userID).Scan, &t)
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
	var t Tenant
	err := scanTenant(p.QueryRow(ctx, `SELECT `+tenantCols+` FROM tenants WHERE slug = $1`, slug).Scan, &t)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// TenantEntitlement is the computed access decision for a tenant.
// Denied=true means the gateway must reject the request with Reason.
type TenantEntitlement struct {
	Tenant *Tenant
	Denied bool
	Reason string
	// TrialEnded reports that a trialing tenant is past trial_ends_at but
	// not yet canceled (Stripe webhook may lag by seconds).
	TrialEnded bool
}

// Entitlement reports whether a tenant may use the gateway right now. It
// reads only the tenant row, so each request sees the status the Stripe
// webhook last wrote.
func (p *Pool) Entitlement(ctx context.Context, t *Tenant) (*TenantEntitlement, error) {
	return EvaluateEntitlement(t, time.Now()), nil
}

// EvaluateEntitlement is the access rule, kept pure so it can be tested:
//   - suspended: denied with reason account_suspended (checked FIRST, before
//     the billing status, so a suspended tenant cannot ride an active
//     subscription or a running trial).
//   - active   : allowed.
//   - trialing : allowed while trial_ends_at is in the future.
//   - past_due : allowed until past_due_since + PastDueGrace (3 days). A
//     past_due tenant without past_due_since is denied (fail closed).
//   - pending_verification: denied with reason email_unverified (403 at the gateway).
//   - anything else (canceled, unpaid, incomplete, paused, unknown): denied.
func EvaluateEntitlement(t *Tenant, now time.Time) *TenantEntitlement {
	e := &TenantEntitlement{Tenant: t}
	deny := func(reason string) *TenantEntitlement {
		e.Denied = true
		e.Reason = reason
		return e
	}
	// Admin suspension outranks every billing status (migration 0008).
	if t.SuspendedAt != nil {
		return deny("account_suspended")
	}
	switch t.Status {
	case TenantActive:
		return e
	case TenantTrialing:
		if t.TrialEndsAt != nil && now.Before(*t.TrialEndsAt) {
			return e
		}
		e.TrialEnded = true
		return deny("trial_ended")
	case TenantPastDue:
		if t.PastDueSince != nil && now.Before(t.PastDueSince.Add(PastDueGrace)) {
			return e
		}
		return deny("payment_overdue")
	case TenantUnpaid:
		return deny("payment_overdue")
	case TenantIncomplete:
		return deny("payment_required")
	case TenantPaused:
		return deny("subscription_paused")
	case TenantCanceled:
		return deny("subscription_canceled")
	case TenantPendingVerification:
		return deny("email_unverified")
	default:
		return deny("unknown_tenant_status")
	}
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

// TryBumpUsage atomically reserves one call against the daily cap
// (Fix 11: closes the read-then-bump TOCTOU). Returns true when the
// reservation succeeded (call allowed), false when the cap is exhausted.
func (p *Pool) TryBumpUsage(ctx context.Context, tenantID string, cap int64) (bool, error) {
	// Fast path: row exists and is under cap.
	tag, err := p.Exec(ctx, `
		UPDATE usage_daily SET calls = calls + 1
		WHERE tenant_id = $1 AND day = current_date AND calls < $2`,
		tenantID, cap)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() > 0 {
		return true, nil
	}
	// No row yet -> create one (idempotent); or row exists at cap -> deny.
	tag, err = p.Exec(ctx, `
		INSERT INTO usage_daily (tenant_id, day, calls) VALUES ($1, current_date, 1)
		ON CONFLICT (tenant_id, day) DO NOTHING`,
		tenantID)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() > 0 {
		return true, nil
	}
	// Row existed but UPDATE matched 0 -> at or above cap.
	return false, nil
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
