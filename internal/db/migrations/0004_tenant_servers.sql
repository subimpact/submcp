-- 0004_tenant_servers.sql
-- SaaS phase 4: tenant self-serve upstreams. Additive only (nullable or
-- defaulted columns), so the image still running during a blue/green switch
-- keeps working. Idempotent.
--
-- tenant_managed: the row was created or last written through the tenant API.
--   Tenant-managed upstreams use the strict network policy (public HTTPS only,
--   checked at dial time). Operator rows keep tenant_managed = false and the
--   legacy policy.
-- last_error / last_checked_at: result of the most recent test or tools/list
--   fetch, shown to the tenant.
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS tenant_managed boolean NOT NULL DEFAULT false;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS last_error text;
ALTER TABLE mcp_servers ADD COLUMN IF NOT EXISTS last_checked_at timestamptz;
