-- 0003_api_keys_user_backfill.sql
-- Fix 7 (P1): migration 0002 backfilled mcp_servers/namespaces/endpoints
-- to the operator but MISSED api_keys - operator keys stayed user_id NULL,
-- so endpoints the operator created got NULL user_id and (per the auth
-- tenant check) became reachable by ANY tenant's API key.
-- Idempotent: safe to run multiple times.
UPDATE api_keys SET user_id = (SELECT id FROM users WHERE email = 'me@subimpact.net')
WHERE user_id IS NULL;
