-- 0001_rbac_and_key_hash.sql
-- RBAC (is_admin) + key hashing (key_hash) + index.
-- Idempotent: safe to run multiple times.

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS is_admin boolean NOT NULL DEFAULT false;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS key_hash text;

-- One-shot backfill: hash every existing key. New keys are hashed at
-- creation time (see db.CreateAPIKey).
UPDATE api_keys SET key_hash = encode(sha256(key::bytea), 'hex') WHERE key_hash IS NULL;

CREATE INDEX IF NOT EXISTS api_keys_key_hash_idx ON api_keys (key_hash);

-- Single-tenant present: enumerate the operator keys as admin.
-- (Deliberately NOT "all keys" — consumer keys stay non-admin.)
UPDATE api_keys SET is_admin = true WHERE name IN ('mcp', 'hermes', 'work', 'jeremy-login');
