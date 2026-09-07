-- 0002_tenants_and_usage.sql
-- Multi-tenant SaaS foundation: tenant registry + daily usage counters.
-- Idempotent: safe to run multiple times.
--
-- tenants: one row per tenant. user_id links to the existing users table
-- (Better Auth schema). slug is the tenant subdomain (tenant.mcp.subimpact.net).
-- status lifecycle: trialing -> active -> past_due -> canceled
--   trialing : within trial_ends_at; gateway allows (usage-capped)
--   active   : paid subscription current
--   past_due : invoice failed; gateway suspends after grace
--   canceled : subscription ended; gateway denies (data kept 30 days)
CREATE TABLE IF NOT EXISTS tenants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id text NOT NULL UNIQUE,
    slug text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'trialing',
    trial_ends_at timestamptz,
    stripe_customer_id text,
    stripe_subscription_id text,
    plan text NOT NULL DEFAULT 'pro',
    subscription_ends_at timestamptz,
    canceled_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Daily per-tenant tool-call counters (trial abuse cap ~1K calls/day).
CREATE TABLE IF NOT EXISTS usage_daily (
    tenant_id uuid NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    day date NOT NULL,
    calls bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day)
);

-- Stripe webhook idempotency log (event_id dedupe).
CREATE TABLE IF NOT EXISTS stripe_events (
    event_id text PRIMARY KEY,
    type text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now()
);

-- Seed the operator tenant (single-tenant compatibility: the existing
-- subimpact user keeps full access; status 'active' = never suspended).
INSERT INTO tenants (user_id, slug, status)
SELECT id, 'subimpact', 'active' FROM users WHERE email = 'me@subimpact.net'
ON CONFLICT (user_id) DO NOTHING;

-- Make the operator the owner of any legacy NULL-user_id rows
-- (single-tenant deployments: everything becomes the operator's).
UPDATE mcp_servers SET user_id = (SELECT id FROM users WHERE email = 'me@subimpact.net')
WHERE user_id IS NULL;
UPDATE namespaces SET user_id = (SELECT id FROM users WHERE email = 'me@subimpact.net')
WHERE user_id IS NULL;
UPDATE endpoints SET user_id = (SELECT id FROM users WHERE email = 'me@subimpact.net')
WHERE user_id IS NULL;

CREATE INDEX IF NOT EXISTS tenants_slug_idx ON tenants (slug);
CREATE INDEX IF NOT EXISTS usage_daily_tenant_day_idx ON usage_daily (tenant_id, day);
