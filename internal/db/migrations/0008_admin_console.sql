-- 0008_admin_console.sql
-- SaaS admin console: suspension flag and the audit trail for admin actions.
-- Additive and idempotent. Each migration runs in its own transaction.
SET LOCAL lock_timeout = '5s';

-- Suspension is deliberately NOT a tenants.status value: the Stripe webhooks
-- rewrite status, and a webhook could silently clear a status-coded
-- suspension. suspended_at is orthogonal billing state the gateway denies on
-- before anything else.
ALTER TABLE tenants
    ADD COLUMN IF NOT EXISTS suspended_at timestamptz,
    ADD COLUMN IF NOT EXISTS suspended_reason text;

-- Every admin action the control plane takes lands here. No foreign keys:
-- audit rows must outlive the customers they refer to (delete keeps history).
CREATE TABLE IF NOT EXISTS admin_audit (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    admin_email text NOT NULL,
    action text NOT NULL,
    tenant_id uuid,
    user_id text,
    slug text,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS admin_audit_at_idx ON admin_audit (at DESC);
CREATE INDEX IF NOT EXISTS admin_audit_tenant_idx ON admin_audit (tenant_id, at DESC);