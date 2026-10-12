-- 0005_tenant_past_due_since.sql
-- SaaS phase 4: past-due grace is anchored on when the tenant BECAME past_due,
-- not on current_period_end (Stripe advances that at each renewal, so a failed
-- renewal used to keep access for about a month).
--
-- Invariant: past_due_since is set exactly while status = 'past_due'. The
-- billing writer sets it on the transition into past_due and clears it on any
-- other status. Additive and idempotent.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS past_due_since timestamptz;

-- Backfill tenants already past_due: the time their status last changed is the
-- closest known start of the failed-payment period.
UPDATE tenants SET past_due_since = COALESCE(updated_at, now())
WHERE status = 'past_due' AND past_due_since IS NULL;
