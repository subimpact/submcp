-- 0006_saas_hardening.sql
-- SaaS phase 4b. Idempotent where the statement allows it.
--
-- 1. Stripe recency guard (SaaS #7): the creation time of the newest Stripe
--    event applied to a tenant. An older event cannot overwrite the state that a
--    newer one already wrote. NULL = no event applied yet.
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS stripe_event_at timestamptz;

-- 2. Session tokens are stored as SHA-256 digests (SaaS #17). The rows written
--    before this change hold raw tokens, so they are removed: every browser
--    logs in once more. No customer data is lost (sessions carry no state).
DELETE FROM sessions;
