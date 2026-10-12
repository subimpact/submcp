-- 0007_signup_gate.sql
-- SaaS phase 4d: email verification and password reset.
-- Additive and idempotent. Each migration runs in its own transaction.
SET LOCAL lock_timeout = '5s';

-- When the address was confirmed. The trial starts at this moment, and the
-- daily signup summary counts verifications from it.
ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at timestamptz;

-- Single-use links (verify an address, reset a password). Only the SHA-256
-- digest of the token is stored; the raw token exists only in the email.
-- A row is spent by setting used_at, which the consuming UPDATE does in the
-- same statement that checks used_at IS NULL and expires_at > now().
CREATE TABLE IF NOT EXISTS auth_tokens (
    digest text PRIMARY KEY,
    user_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('verify', 'reset')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);
CREATE INDEX IF NOT EXISTS auth_tokens_user_purpose_idx
    ON auth_tokens (user_id, purpose, created_at);

-- Every account that exists when this migration runs predates the gate, so it
-- counts as verified (the operator's tenant "subimpact" among them). New
-- signups start with email_verified = false and tenant status
-- 'pending_verification' until the link is used.
UPDATE users
   SET email_verified = true,
       email_verified_at = COALESCE(email_verified_at, now()),
       updated_at = now()
 WHERE email_verified = false;
