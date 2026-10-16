#!/bin/bash
# Blue/green deploy for submcp-prod (gate 9; SaaS 4c rewrite).
#
# Strategy (each colour is created under a name, attached, health-checked, then
# switched; at every step at least one healthy backend serves Traefik):
#   1. Start submcp-prod-next (probe 127.0.0.1:12009). Traefik now load-balances
#      old + new -> public https://mcp.subimpact.net never drops.
#   2. Wait for the new container to pass its health check and bind its uy2 and
#      internal addresses (logs are checked, not assumed).
#   3. Verify the public URL serves the new build (warn only: Traefik may still
#      be routing to the old colour).
#   4. Retire the OLD container. submcp-prod-next is now the only backend.
#   5. Create the new prod under a TEMPORARY name (submcp-prod-stage) with the
#      host port 127.0.0.1:12008 (Tailscale serve target) and the prod addresses,
#      attach its networks, start it, health-check it. A failure here removes the
#      stage and leaves submcp-prod-next serving (zero backends never happens).
#   6. Switch: remove submcp-prod-next, rename the stage to submcp-prod.
#   7. Verify all entry points, and that a direct request to the origin from a
#      non-Cloudflare address is refused (N1).
#
# Rollback: ./scripts/deploy-blue-green.sh submcp:prev
#
# Required order for a new build. The rollback target must be tagged BEFORE
# the build retags submcp:prod, because an untagged image can vanish from the
# image store (it did once; nothing was left to roll back to):
#   docker tag submcp:prod submcp:prev     # protect the live image
#   docker build -t submcp:prod .
#   ./scripts/deploy-blue-green.sh
# This script also tags the live container's image as submcp:prev when it can.
#
# Dry run (no docker changes; prints the plan): DRY_RUN=1 ./scripts/deploy-blue-green.sh
#
# Networking detail: uy2 is attached at create with the default gateway priority;
# every other network is attached with --gw-priority -1. Docker maps published
# ports (127.0.0.1:12008, the Tailscale and Hermes path) through the gateway
# network, so this keeps the mapping on the uy2 address the process listens on.
#
# Network exposure (SaaS 4c):
#   - Each colour has a fixed address on the uy2 network (Traefik's network):
#     prod 10.0.5.20, next 10.0.5.21. The process binds ONLY that address
#     (LISTEN_ADDR), so a container on `shared` cannot reach :12008 (N11).
#   - The apex routers (mcp.subimpact.net, app.subimpact.net) carry an
#     ipAllowList middleware with Cloudflare's published ranges (N1). Traefik
#     checks the TCP peer, not a forwarded header, so a direct request to the
#     origin with a spoofed CF-Connecting-IP is refused.
#   - Tenant hosts (*.mcp.subimpact.net) are DNS-only and stay reachable.
#   - TRUSTED_PROXY_CIDRS is Traefik's exact uy2 address, read from docker at
#     deploy time (N10). Traefik's address is not pinned: a Traefik restart can
#     change it, so re-run this script after a Traefik restart.
#
# Secrets never appear in argv: they go through a mode-600 --env-file that is
# removed on exit. Container creation order: `docker create` with the uy2
# address, attach the other networks, then `docker start` (the process binds
# its addresses at start, so they must exist first).
set -e

cd "$(dirname "$0")/.."

DRY_RUN="${DRY_RUN:-0}"
run_docker() {
  if [ "$DRY_RUN" = 1 ]; then
    echo "    [dry-run] docker $*" >&2
  else
    docker "$@"
  fi
}

# Load local secrets (gitignored).
if [ -f .env.prod ]; then
  set -a
  # shellcheck disable=SC1091
  source .env.prod
  set +a
fi

: "${POSTGRES_USER:?POSTGRES_USER must be set (see .env.prod.example)}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set (see .env.prod.example)}"
: "${POSTGRES_DB:=metamcp_db}"
: "${POSTGRES_HOST:=postgres}"
: "${POSTGRES_PORT:=5432}"
# Tenant mode is ON only when TENANT_BASE_HOST is set; an empty value would
# silently fall back to the single-tenant lookup for every subdomain.
: "${TENANT_BASE_HOST:=mcp.subimpact.net}"
: "${TRIAL_DAILY_LIMIT:=1000}"
# SaaS phase 4. The service token authenticates the SaaS dashboard on the
# internal listener; the secret key seals tenant credentials at rest. Both are
# required: a deploy without them would silently disable the tenant API.
: "${TENANT_API_SERVICE_TOKEN:?TENANT_API_SERVICE_TOKEN must be set (openssl rand -hex 32; see .env.prod.example)}"
: "${TENANT_SECRET_KEY:?TENANT_SECRET_KEY must be set (openssl rand -base64 32; see .env.prod.example)}"
: "${TENANT_MAX_SERVERS:=10}"
: "${TENANT_TEST_PER_MINUTE:=10}"
: "${TENANT_POOL_BUDGET:=30}"
# Per-tenant share of the pool (SaaS 4c, N2): at most 3 connections in use per
# tenant, so 8 saturating tenants cannot take the whole tenant budget.
: "${TENANT_NS_IN_FLIGHT:=3}"
# R3: admin Cloudflare Access login, optional. NO :? guards here: any
# missing setting disables JWT admin login (the API-key login stays), so a
# deploy must never fail because of it. ACCESS_CERTS_URL is optional too;
# when the team domain is set the default certs endpoint is derived from it.
: "${ACCESS_TEAM_DOMAIN:=}"
: "${ACCESS_AUD:=}"
: "${ADMIN_EMAILS:=}"
: "${ACCESS_CERTS_URL:=}"

IMAGE="${1:-submcp:prod}"

UY2_NET=uy2gf2yhgu9cqi16y69is4ni
SHARED_NET=shared
TRAEFIK_CONTAINER=traefik-standalone
# Fixed addresses on uy2 (see the header). Both colours are in 10.0.5.0/24 and
# outside the addresses Docker hands out dynamically to the other stacks.
UY2_IP_PROD=10.0.5.20
UY2_IP_NEXT=10.0.5.21

# Same-host upstreams that live on another compose network. A container that
# is recreated without these networks cannot resolve the upstream (pitfall 15):
# the matrix MCP server (matrix-mcp) lives on the Matrix stack network, and
# dropping it cut 20 operator tools until it was reattached. Every deploy
# attaches them to the new container, idempotently.
UPSTREAM_NETWORKS=(urhxt3a4nix782v8eo5da1cb)
attach_upstream_networks() {
  local net
  for net in "${UPSTREAM_NETWORKS[@]}"; do
    if ! docker inspect -f '{{json .NetworkSettings.Networks}}' "$1" 2>/dev/null | grep -q "\"$net\""; then
      run_docker network connect --gw-priority -1 "$net" "$1" || echo "WARN: could not attach $1 to $net" >&2
    fi
  done
}

# --- Traefik's address (N10) --------------------------------------------------
# The gateway trusts forwarded client headers only from Traefik's exact address.
# Read from docker now; refuse to deploy without it (the trust list would be
# empty, and Cloudflare clients would all be attributed to Traefik).
TRAEFIK_IP="$(docker inspect -f '{{with index .NetworkSettings.Networks "'"$UY2_NET"'"}}{{.IPAddress}}{{end}}' "$TRAEFIK_CONTAINER" 2>/dev/null || true)"
if ! [[ "$TRAEFIK_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: could not read Traefik's address on $UY2_NET (container $TRAEFIK_CONTAINER)" >&2
  exit 1
fi
TRUSTED_PROXY_CIDRS="${TRAEFIK_IP}/32"
echo "==> Traefik is ${TRAEFIK_IP} on uy2: TRUSTED_PROXY_CIDRS=${TRUSTED_PROXY_CIDRS}"

# --- Cloudflare ranges (N1) ----------------------------------------------------
# Cloudflare publishes its ranges at https://www.cloudflare.com/ips-v4 and
# /ips-v6. They are fetched at deploy time. The snapshot below is the fallback
# when the fetch fails or returns something that is not a CIDR list.
CF_SNAPSHOT_DATE=2026-10-12
CF_SNAPSHOT="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32"
cf_ranges() {
  local ua="Mozilla/5.0 (X11; Linux x86_64) submcp-deploy" v4 v6 all
  v4="$(curl -sf -m 10 -A "$ua" https://www.cloudflare.com/ips-v4 2>/dev/null || true)"
  v6="$(curl -sf -m 10 -A "$ua" https://www.cloudflare.com/ips-v6 2>/dev/null || true)"
  all="$(printf '%s\n%s\n' "$v4" "$v6" | tr -d '\r' | awk 'NF')"
  local n bad
  n="$(printf '%s\n' "$all" | grep -Ec '^[0-9a-fA-F:.]+/[0-9]{1,3}$' || true)"
  bad="$(printf '%s\n' "$all" | grep -Evc '^[0-9a-fA-F:.]+/[0-9]{1,3}$' || true)"
  if [ "$n" -ge 20 ] && [ "$bad" = 0 ]; then
    printf '%s\n' "$all" | paste -sd, -
  else
    echo "WARN: Cloudflare ranges not fetched (got $n CIDRs); using the snapshot of $CF_SNAPSHOT_DATE" >&2
    echo "$CF_SNAPSHOT" | tr ' ' ','
  fi
}
CF_RANGES="$(cf_ranges)"
echo "==> Cloudflare allowlist: $(echo "$CF_RANGES" | tr ',' '\n' | wc -l) ranges"

# --- Internal tenant network (SaaS phase 4b, #5) -----------------------------
# submcp-internal is an --internal bridge: no route to the outside and no host
# port. Only the gateway (both colours) and the SaaS attach to it. The gateway's
# service listener binds the gateway's own address on it (10.77.0.10 / .11), so
# a container on any other network cannot reach it, and nothing else is on it.
INTERNAL_NET=submcp-internal
INTERNAL_SUBNET=10.77.0.0/24
INTERNAL_IP_PROD=10.77.0.10     # submcp-prod (the colour serving traffic)
INTERNAL_IP_NEXT=10.77.0.11     # submcp-prod-next (the colour being rolled out)
INTERNAL_ALIAS=submcp-gateway-internal
if ! docker network inspect "$INTERNAL_NET" >/dev/null 2>&1; then
  echo "==> creating $INTERNAL_NET ($INTERNAL_SUBNET, internal)"
  run_docker network create --internal --subnet "$INTERNAL_SUBNET" "$INTERNAL_NET" >/dev/null
fi

# Rollback target: tag the image the LIVE submcp-prod container runs. Not the
# submcp:prod tag, which the build being deployed has usually replaced already.
# Skipped when rolling back (IMAGE=submcp:prev) so the target is never
# overwritten with the bad image. If the live image is no longer in the image
# store, keep the existing submcp:prev and warn (see the order above).
if [ "$IMAGE" != "submcp:prev" ]; then
  LIVE_IMG="$(docker inspect -f '{{.Image}}' submcp-prod 2>/dev/null || true)"
  if [ -n "$LIVE_IMG" ] && run_docker tag "$LIVE_IMG" submcp:prev 2>/dev/null; then
    echo "==> submcp:prev = live image ${LIVE_IMG:7:12}"
  else
    echo "WARN: live image not tagged as submcp:prev; keeping the existing submcp:prev" >&2
  fi
fi

LABELS=(
  "traefik.docker.network=$UY2_NET"
  "traefik.enable=true"
  "traefik.http.middlewares.gzip.compress=true"
  "traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https"
  # N1: the apex accepts only Cloudflare's addresses (TCP peer, not a header).
  # Defined in both deploy scripts with the same ranges.
  "traefik.http.middlewares.cf-only.ipallowlist.sourcerange=$CF_RANGES"
  "traefik.http.routers.http-0-submcp-prod-next.entryPoints=http"
  "traefik.http.routers.http-0-submcp-prod-next.middlewares=cf-only,redirect-to-https"
  "traefik.http.routers.http-0-submcp-prod-next.rule=Host(\`mcp.subimpact.net\`) && PathPrefix(\`/\`)"
  "traefik.http.routers.http-0-submcp-prod-next.service=http-0-submcp-prod-next"
  "traefik.http.routers.https-0-submcp-prod-next.entryPoints=https"
  "traefik.http.routers.https-0-submcp-prod-next.middlewares=cf-only,gzip"
  "traefik.http.routers.https-0-submcp-prod-next.rule=Host(\`mcp.subimpact.net\`) && PathPrefix(\`/\`)"
  "traefik.http.routers.https-0-submcp-prod-next.service=https-0-submcp-prod-next"
  "traefik.http.routers.https-0-submcp-prod-next.tls=true"
  "traefik.http.routers.https-0-submcp-prod-next.tls.certresolver=letsencrypt"
  "traefik.http.services.http-0-submcp-prod-next.loadbalancer.server.port=12008"
  "traefik.http.services.https-0-submcp-prod-next.loadbalancer.server.port=12008"
  # Tenant subdomains (SaaS): *.mcp.subimpact.net -> the same gateway container.
  # One label before .mcp.subimpact.net; the bare host never matches. Tenant
  # hosts are DNS-only (not behind Cloudflare), so no allowlist applies here.
  "traefik.http.routers.http-1-submcp-tenant-next.entryPoints=http"
  "traefik.http.routers.http-1-submcp-tenant-next.middlewares=redirect-to-https"
  "traefik.http.routers.http-1-submcp-tenant-next.rule=HostRegexp(\`^[a-z0-9-]+\\.mcp\\.subimpact\\.net\$\`) && !PathPrefix(\`/admin\`) && !PathPrefix(\`/api/admin\`)"
  "traefik.http.routers.http-1-submcp-tenant-next.service=http-1-submcp-tenant-next"
  "traefik.http.routers.http-1-submcp-tenant-next.priority=2"
  "traefik.http.routers.https-1-submcp-tenant-next.entryPoints=https"
  "traefik.http.routers.https-1-submcp-tenant-next.middlewares=gzip"
  "traefik.http.routers.https-1-submcp-tenant-next.rule=HostRegexp(\`^[a-z0-9-]+\\.mcp\\.subimpact\\.net\$\`) && !PathPrefix(\`/admin\`) && !PathPrefix(\`/api/admin\`)"
  "traefik.http.routers.https-1-submcp-tenant-next.service=https-1-submcp-tenant-next"
  "traefik.http.routers.https-1-submcp-tenant-next.priority=2"
  "traefik.http.routers.https-1-submcp-tenant-next.tls=true"
  "traefik.http.routers.https-1-submcp-tenant-next.tls.certresolver=letsencrypt"
  # ONE wildcard certificate via the letsencrypt DNS-01 resolver (Cloudflare),
  # not per-host issuance.
  "traefik.http.routers.https-1-submcp-tenant-next.tls.domains[0].main=mcp.subimpact.net"
  "traefik.http.routers.https-1-submcp-tenant-next.tls.domains[0].sans=*.mcp.subimpact.net"
  "traefik.http.services.http-1-submcp-tenant-next.loadbalancer.server.port=12008"
  "traefik.http.services.https-1-submcp-tenant-next.loadbalancer.server.port=12008"
)

ARGS=()
for l in "${LABELS[@]}"; do
  ARGS+=(--label "$l")
done
# Promote set: each label renamed once (-next -> prod). Renaming in a single
# pass keeps the prod container free of stale -next router names. The stage
# container carries these labels from the start, so it is routed as prod.
PROD_ARGS=()
for l in "${LABELS[@]}"; do
  l="${l//submcp-prod-next/submcp-prod}"
  l="${l//submcp-tenant-next/submcp-tenant-prod}"
  PROD_ARGS+=(--label "$l")
done

# Secrets and shared settings go in a mode-600 env file, never in argv (argv is
# visible in `ps` and in `docker inspect`). Removed on exit. LISTEN_ADDR is not
# in the file: it depends on the colour (its uy2 address).
ENV_FILE="$(mktemp)"
chmod 600 "$ENV_FILE"
trap 'rm -f "$ENV_FILE"' EXIT
cat > "$ENV_FILE" <<ENVEOF
POSTGRES_HOST=$POSTGRES_HOST
POSTGRES_PORT=$POSTGRES_PORT
POSTGRES_USER=$POSTGRES_USER
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=$POSTGRES_DB
TENANT_BASE_HOST=$TENANT_BASE_HOST
TRIAL_DAILY_LIMIT=$TRIAL_DAILY_LIMIT
TENANT_API_SERVICE_TOKEN=$TENANT_API_SERVICE_TOKEN
TENANT_SECRET_KEY=$TENANT_SECRET_KEY
TENANT_MAX_SERVERS=$TENANT_MAX_SERVERS
TENANT_TEST_PER_MINUTE=$TENANT_TEST_PER_MINUTE
TENANT_POOL_BUDGET=$TENANT_POOL_BUDGET
TENANT_NS_IN_FLIGHT=$TENANT_NS_IN_FLIGHT
TRUSTED_PROXY_CIDRS=$TRUSTED_PROXY_CIDRS
ACCESS_TEAM_DOMAIN=$ACCESS_TEAM_DOMAIN
ACCESS_AUD=$ACCESS_AUD
ADMIN_EMAILS=$ADMIN_EMAILS
ACCESS_CERTS_URL=$ACCESS_CERTS_URL
ENVEOF

# Create a gateway container with its uy2 address, attach the other networks,
# then start it. The listeners bind their addresses at start, so every network
# must be attached before `docker start`. Memory is capped at 1g (the cap bounds
# a hostile tools/list, SaaS phase 4b #6).
create_gateway() {
  local name="$1" hostport="$2" uy2ip="$3" internalip="$4"
  shift 4
  run_docker create --name "$name" --restart unless-stopped \
    --memory 1g --memory-swap 1g \
    --network "$UY2_NET" --ip "$uy2ip" --network-alias submcp-gateway \
    -p "127.0.0.1:${hostport}:12008" \
    --env-file "$ENV_FILE" \
    -e LISTEN_ADDR="${uy2ip}:12008" \
    -e TENANT_API_INTERNAL_ADDR="${internalip}:12013" \
    "$@" \
    "$IMAGE" >/dev/null
  # Only uy2 provides the default gateway: Docker maps published ports through
  # the gateway network, so without this the 127.0.0.1:<port> mapping would
  # point at the shared address, where nothing listens (N11).
  run_docker network connect --gw-priority -1 "$SHARED_NET" "$name"
  run_docker network connect --gw-priority -1 --ip "$internalip" --alias "$INTERNAL_ALIAS" "$INTERNAL_NET" "$name"
  attach_upstream_networks "$name"
  run_docker start "$name" >/dev/null
}

# wait_healthy <container> <probe port> <uy2 address> <internal address>
# Passes only when the health probe answers AND the logs show both listeners
# bound to the expected addresses (not just that the process runs).
wait_healthy() {
  local name="$1" port="$2" uy2ip="$3" internalip="$4" i
  if [ "$DRY_RUN" = 1 ]; then echo "    [dry-run] would wait for $name on 127.0.0.1:$port"; return 0; fi
  for i in $(seq 1 30); do
    if curl -sf -o /dev/null -m 3 "http://127.0.0.1:${port}/health"; then
      echo "    healthy after ${i}s"
      break
    fi
    if [ "$i" = 30 ]; then
      echo "ERROR: $name never became healthy" >&2
      docker logs "$name" 2>&1 | tail -20
      return 1
    fi
    sleep 1
  done
  if ! docker logs "$name" 2>&1 | grep -q "submcp listening on ${uy2ip}:12008"; then
    echo "ERROR: $name is not bound to ${uy2ip}:12008 (see logs)" >&2
    docker logs "$name" 2>&1 | tail -20
    return 1
  fi
  if ! docker logs "$name" 2>&1 | grep -q "tenant API (service auth) listening on ${internalip}:12013"; then
    echo "ERROR: $name internal listener is not bound to ${internalip}:12013 (see logs)" >&2
    docker logs "$name" 2>&1 | tail -20
    return 1
  fi
  echo "    bound to ${uy2ip}:12008 (uy2) and ${internalip}:12013 (${INTERNAL_NET})"
}

echo "==> [1/7] starting submcp-prod-next (probe 127.0.0.1:12009, uy2 ${UY2_IP_NEXT}, internal ${INTERNAL_IP_NEXT})"
run_docker rm -f submcp-prod-next >/dev/null 2>&1 || true
create_gateway submcp-prod-next 12009 "$UY2_IP_NEXT" "$INTERNAL_IP_NEXT" "${ARGS[@]}"
wait_healthy submcp-prod-next 12009 "$UY2_IP_NEXT" "$INTERNAL_IP_NEXT" || {
  echo "ERROR: the new build did not start; the live colour is untouched" >&2
  run_docker rm -f submcp-prod-next >/dev/null 2>&1 || true
  exit 1
}

echo "==> [2/7] verifying public URL serves the new build"
# The landing page title is a marker for the new build (old image has no
# landing page at /).
if [ "$DRY_RUN" != 1 ]; then
  if ! curl -sf -m 8 -A "Mozilla/5.0 (X11; Linux x86_64) submcp-deploy" https://mcp.subimpact.net/ | grep -q "submcp - the single-binary MCP gateway"; then
    echo "WARN: public URL did not show the new landing page marker (may still be LB-ing to old)" >&2
  fi
  curl -sf -o /dev/null -m 8 -A "Mozilla/5.0 (X11; Linux x86_64) submcp-deploy" https://mcp.subimpact.net/health && echo "    public health OK"
fi

echo "==> [3/7] retiring the old colour (submcp-prod-next now serves alone)"
run_docker stop submcp-prod >/dev/null 2>&1 || true
run_docker rm submcp-prod >/dev/null 2>&1 || true

echo "==> [4/7] creating the new prod as submcp-prod-stage (host 12008, uy2 ${UY2_IP_PROD}, internal ${INTERNAL_IP_PROD})"
run_docker rm -f submcp-prod-stage >/dev/null 2>&1 || true
if ! create_gateway submcp-prod-stage 12008 "$UY2_IP_PROD" "$INTERNAL_IP_PROD" "${PROD_ARGS[@]}"; then
  echo "ERROR: the new prod could not be created or attached; removing it. submcp-prod-next still serves." >&2
  run_docker rm -f submcp-prod-stage >/dev/null 2>&1 || true
  exit 1
fi
if ! wait_healthy submcp-prod-stage 12008 "$UY2_IP_PROD" "$INTERNAL_IP_PROD"; then
  echo "ERROR: the new prod failed its health check; removing it. submcp-prod-next still serves." >&2
  run_docker rm -f submcp-prod-stage >/dev/null 2>&1 || true
  exit 1
fi

echo "==> [5/7] switching: remove submcp-prod-next, rename submcp-prod-stage to submcp-prod"
run_docker rm -f submcp-prod-next >/dev/null 2>&1 || true
run_docker rename submcp-prod-stage submcp-prod

echo "==> [6/7] verifying all entry points"
if [ "$DRY_RUN" = 1 ]; then echo "    [dry-run] stopping before the live checks"; exit 0; fi
for i in $(seq 1 30); do
  if curl -sf -o /dev/null -m 3 http://127.0.0.1:12008/health; then
    echo "    host health OK (${i}s)"
    break
  fi
  [ "$i" = 30 ] && { echo "ERROR: prod never healthy" >&2; exit 1; }
  sleep 1
done
# Traefik routes to the renamed container a few seconds after the switch: retry
# the public checks (pitfalls 1 and 21) instead of treating the first miss as a failure.
for i in $(seq 1 30); do
  if curl -sf -o /dev/null -m 8 -A "Mozilla/5.0 (X11; Linux x86_64) submcp-deploy" https://mcp.subimpact.net/health; then
    echo "    public OK (${i}s)"
    break
  fi
  [ "$i" = 30 ] && echo "WARN: public health not answering after 30s; check Traefik" >&2
  sleep 1
done
curl -sf -o /dev/null -m 8 https://vmi3274017-vps.tailab0a04.ts.net:12008/health && echo "    tailscale OK"
# Tenant wildcard: the cert may still be issuing (DNS-01 takes a minute or
# two). Warn, do not fail; re-check with a strict curl once it settles.
curl -sf -o /dev/null -m 8 -A "Mozilla/5.0 (X11; Linux x86_64) submcp-deploy" https://subimpact.mcp.subimpact.net/health && echo "    tenant host OK" \
  || echo "WARN: tenant host not serving yet (wildcard cert may still be issuing)" >&2

echo "==> [7/7] origin guard (N1): a direct request from a non-Cloudflare address must be refused"
# The origin address is the one Traefik publishes 443 on (read from docker).
ORIGIN_IP="$(docker inspect -f '{{with index .NetworkSettings.Ports "443/tcp"}}{{(index . 0).HostIp}}{{end}}' "$TRAEFIK_CONTAINER" 2>/dev/null || true)"
if [[ "$ORIGIN_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  code=""
  for i in $(seq 1 30); do
    code="$(curl -s -o /dev/null -m 8 -w '%{http_code}' -A "Mozilla/5.0 (X11; Linux x86_64) submcp-deploy" \
      --resolve "mcp.subimpact.net:443:${ORIGIN_IP}" https://mcp.subimpact.net/health || true)"
    [ "$code" = 403 ] && break
    sleep 1
  done
  if [ "$code" = 403 ]; then
    echo "    direct origin request from ${ORIGIN_IP}: 403 (refused, as intended)"
  else
    echo "ERROR: direct origin request from ${ORIGIN_IP} answered ${code}, expected 403 (the Cloudflare allowlist is not in force)" >&2
    exit 1
  fi
else
  echo "WARN: could not determine this host's public address; origin guard not checked" >&2
fi
echo "==> done. rollback: ./scripts/deploy-blue-green.sh submcp:prev"
