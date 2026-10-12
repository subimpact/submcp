#!/bin/bash
# Blue/green deploy for submcp-prod (gate 9).
#
# Strategy:
#   1. Start submcp-prod-next with the SAME Traefik labels (suffixed -next)
#      on the docker network, probe port 127.0.0.1:12009. Traefik now
#      load-balances old + new -> public https://mcp.subimpact.net never
#      drops.
#   2. Wait for the new container to pass its healthcheck.
#   3. Verify the public URL serves the new build.
#   4. Stop + remove the OLD container. Traefik routes only to new.
#   5. Recreate the new container as submcp-prod with the host port
#      127.0.0.1:12008 (Tailscale serve target). Brief gap on Tailscale
#      ONLY; public path is unaffected.
#   6. Verify all entry points.
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
# Secrets never appear in argv: they go through a mode-600 --env-file that is
# removed on exit. Container creation order: `docker create`, attach the
# networks (the internal listener binds an address on submcp-internal, which
# must exist before the process starts), then `docker start`.
set -e

cd "$(dirname "$0")/.."

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
: "${TENANT_NS_IN_FLIGHT:=4}"
# Proxies whose forwarded client headers are believed: the uy2 network, where
# Traefik sits (and Postgres and the SaaS, which are not HTTP clients of the
# public listener). Traefik's address can change on restart; a /24 keeps it
# trusted, while an exact address would fall back to one shared rate bucket.
: "${TRUSTED_PROXY_CIDRS:=10.0.5.0/24}"

IMAGE="${1:-submcp:prod}"

# Same-host upstreams that live on another compose network. A container that
# is recreated without these networks cannot resolve the upstream (pitfall 15):
# the matrix MCP server (matrix-mcp) lives on the Matrix stack network, and
# dropping it cut 20 operator tools until it was reattached. Every deploy
# attaches them to the new container, idempotently.
UPSTREAM_NETWORKS=(urhxt3a4nix782v8eo5da1cb)
attach_upstream_networks() {
  local net
  for net in "${UPSTREAM_NETWORKS[@]}"; do
    if ! docker inspect -f '{{json .NetworkSettings.Networks}}' "$1" | grep -q "\"$net\""; then
      docker network connect "$net" "$1" || echo "WARN: could not attach $1 to $net" >&2
    fi
  done
}

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
  docker network create --internal --subnet "$INTERNAL_SUBNET" "$INTERNAL_NET" >/dev/null
fi

# Rollback target: tag the image the LIVE submcp-prod container runs. Not the
# submcp:prod tag, which the build being deployed has usually replaced already.
# Skipped when rolling back (IMAGE=submcp:prev) so the target is never
# overwritten with the bad image. If the live image is no longer in the image
# store, keep the existing submcp:prev and warn (see the order above).
if [ "$IMAGE" != "submcp:prev" ]; then
  LIVE_IMG="$(docker inspect -f '{{.Image}}' submcp-prod 2>/dev/null || true)"
  if [ -n "$LIVE_IMG" ] && docker tag "$LIVE_IMG" submcp:prev 2>/dev/null; then
    echo "==> submcp:prev = live image ${LIVE_IMG:7:12}"
  else
    echo "WARN: live image not tagged as submcp:prev; keeping the existing submcp:prev" >&2
  fi
fi

LABELS=(
  "traefik.docker.network=uy2gf2yhgu9cqi16y69is4ni"
  "traefik.enable=true"
  "traefik.http.middlewares.gzip.compress=true"
  "traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https"
  "traefik.http.routers.http-0-submcp-prod-next.entryPoints=http"
  "traefik.http.routers.http-0-submcp-prod-next.middlewares=redirect-to-https"
  "traefik.http.routers.http-0-submcp-prod-next.rule=Host(\`mcp.subimpact.net\`) && PathPrefix(\`/\`)"
  "traefik.http.routers.http-0-submcp-prod-next.service=http-0-submcp-prod-next"
  "traefik.http.routers.https-0-submcp-prod-next.entryPoints=https"
  "traefik.http.routers.https-0-submcp-prod-next.middlewares=gzip"
  "traefik.http.routers.https-0-submcp-prod-next.rule=Host(\`mcp.subimpact.net\`) && PathPrefix(\`/\`)"
  "traefik.http.routers.https-0-submcp-prod-next.service=https-0-submcp-prod-next"
  "traefik.http.routers.https-0-submcp-prod-next.tls=true"
  "traefik.http.routers.https-0-submcp-prod-next.tls.certresolver=letsencrypt"
  "traefik.http.services.http-0-submcp-prod-next.loadbalancer.server.port=12008"
  "traefik.http.services.https-0-submcp-prod-next.loadbalancer.server.port=12008"
  # Tenant subdomains (SaaS): *.mcp.subimpact.net -> the same gateway container.
  # One label before .mcp.subimpact.net; the bare host never matches.
  "traefik.http.routers.http-1-submcp-tenant-next.entryPoints=http"
  "traefik.http.routers.http-1-submcp-tenant-next.middlewares=redirect-to-https"
  "traefik.http.routers.http-1-submcp-tenant-next.rule=HostRegexp(\`^[a-z0-9-]+\\.mcp\\.subimpact\\.net\$\`)"
  "traefik.http.routers.http-1-submcp-tenant-next.service=http-1-submcp-tenant-next"
  "traefik.http.routers.http-1-submcp-tenant-next.priority=2"
  "traefik.http.routers.https-1-submcp-tenant-next.entryPoints=https"
  "traefik.http.routers.https-1-submcp-tenant-next.middlewares=gzip"
  "traefik.http.routers.https-1-submcp-tenant-next.rule=HostRegexp(\`^[a-z0-9-]+\\.mcp\\.subimpact\\.net\$\`)"
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
# pass keeps the prod container free of stale -next router names.
PROD_ARGS=()
for l in "${LABELS[@]}"; do
  l="${l//submcp-prod-next/submcp-prod}"
  l="${l//submcp-tenant-next/submcp-tenant-prod}"
  PROD_ARGS+=(--label "$l")
done

# Secrets and shared settings go in a mode-600 env file, never in argv (argv is
# visible in `ps` and in `docker inspect`). Removed on exit.
ENV_FILE="$(mktemp)"
chmod 600 "$ENV_FILE"
trap 'rm -f "$ENV_FILE"' EXIT
cat > "$ENV_FILE" <<ENVEOF
POSTGRES_HOST=$POSTGRES_HOST
POSTGRES_PORT=$POSTGRES_PORT
POSTGRES_USER=$POSTGRES_USER
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
POSTGRES_DB=$POSTGRES_DB
LISTEN_ADDR=:12008
TENANT_BASE_HOST=$TENANT_BASE_HOST
TRIAL_DAILY_LIMIT=$TRIAL_DAILY_LIMIT
TENANT_API_SERVICE_TOKEN=$TENANT_API_SERVICE_TOKEN
TENANT_SECRET_KEY=$TENANT_SECRET_KEY
TENANT_MAX_SERVERS=$TENANT_MAX_SERVERS
TENANT_TEST_PER_MINUTE=$TENANT_TEST_PER_MINUTE
TENANT_POOL_BUDGET=$TENANT_POOL_BUDGET
TENANT_NS_IN_FLIGHT=$TENANT_NS_IN_FLIGHT
TRUSTED_PROXY_CIDRS=$TRUSTED_PROXY_CIDRS
ENVEOF

# Create a gateway container, attach its networks, then start it. The internal
# listener binds $ip on submcp-internal, so that network must be attached before
# the process starts. Memory is capped at 1g (RSS was about 12 MiB; the cap bounds
# a hostile tools/list, SaaS phase 4b #6).
create_gateway() {
  local name="$1" hostport="$2" ip="$3"
  shift 3
  docker create --name "$name" --restart unless-stopped \
    --memory 1g --memory-swap 1g \
    --network uy2gf2yhgu9cqi16y69is4ni --network-alias submcp-gateway --network shared \
    -p "127.0.0.1:${hostport}:12008" \
    --env-file "$ENV_FILE" \
    -e TENANT_API_INTERNAL_ADDR="${ip}:12013" \
    "$@" \
    "$IMAGE" >/dev/null
  docker network connect --ip "$ip" --alias "$INTERNAL_ALIAS" "$INTERNAL_NET" "$name"
  attach_upstream_networks "$name"
  docker start "$name" >/dev/null
}

echo "==> [1/6] starting submcp-prod-next (probe port 12009, internal ${INTERNAL_IP_NEXT})"
docker rm -f submcp-prod-next 2>/dev/null || true
create_gateway submcp-prod-next 12009 "$INTERNAL_IP_NEXT" "${ARGS[@]}"

echo "==> [2/6] waiting for health"
for i in $(seq 1 30); do
  if curl -sf -o /dev/null -m 3 http://127.0.0.1:12009/health; then
    echo "    healthy after ${i}s"
    break
  fi
  if [ "$i" = 30 ]; then
    echo "ERROR: new container never became healthy" >&2
    docker logs submcp-prod-next 2>&1 | tail -20
    exit 1
  fi
  sleep 1
done
if ! docker logs submcp-prod-next 2>&1 | grep -q "tenant API (service auth) listening on ${INTERNAL_IP_NEXT}:12013"; then
  echo "ERROR: the internal listener is not bound to ${INTERNAL_IP_NEXT}:12013 (see logs)" >&2
  docker logs submcp-prod-next 2>&1 | tail -20
  exit 1
fi
echo "    internal listener bound to ${INTERNAL_IP_NEXT}:12013 on ${INTERNAL_NET}"

echo "==> [3/6] verifying public URL serves the new build"
# The landing page title is a marker for the new build (old image has no
# landing page at /).
if ! curl -sf -m 8 https://mcp.subimpact.net/ | grep -q "submcp - the single-binary MCP gateway"; then
  echo "WARN: public URL did not show the new landing page marker (may still be LB-ing to old)" >&2
fi
curl -sf -o /dev/null -m 8 https://mcp.subimpact.net/health && echo "    public health OK"

echo "==> [4/6] stopping old container"
docker stop submcp-prod 2>/dev/null || true
docker rm submcp-prod 2>/dev/null || true

echo "==> [5/6] promoting next -> prod with host port 12008 (Tailscale), internal ${INTERNAL_IP_PROD}"
docker rm -f submcp-prod-next 2>/dev/null || true
create_gateway submcp-prod 12008 "$INTERNAL_IP_PROD" "${PROD_ARGS[@]}"

echo "==> [6/6] verifying all entry points"
for i in $(seq 1 30); do
  if curl -sf -o /dev/null -m 3 http://127.0.0.1:12008/health; then
    echo "    host health OK (${i}s)"
    break
  fi
  [ "$i" = 30 ] && { echo "ERROR: prod never healthy" >&2; exit 1; }
  sleep 1
done
if ! docker logs submcp-prod 2>&1 | grep -q "tenant API (service auth) listening on ${INTERNAL_IP_PROD}:12013"; then
  echo "ERROR: submcp-prod internal listener is not on ${INTERNAL_IP_PROD}:12013" >&2
  exit 1
fi
echo "    internal listener bound to ${INTERNAL_IP_PROD}:12013 on ${INTERNAL_NET}"
curl -sf -o /dev/null -m 8 https://mcp.subimpact.net/health && echo "    public OK"
curl -sf -o /dev/null -m 8 https://vmi3274017-vps.tailab0a04.ts.net:12008/health && echo "    tailscale OK"
# Tenant wildcard: the cert may still be issuing (DNS-01 takes a minute or
# two). Warn, do not fail; re-check with a strict curl once it settles.
curl -sf -o /dev/null -m 8 https://subimpact.mcp.subimpact.net/health && echo "    tenant host OK" \
  || echo "WARN: tenant host not serving yet (wildcard cert may still be issuing)" >&2

echo "==> done. rollback: ./scripts/deploy-blue-green.sh submcp:prev"
