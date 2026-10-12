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

IMAGE="${1:-submcp:prod}"

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

# Escaping: inside these double-quoted strings \` is a literal backtick and
# \$ a literal dollar. The HostRegexp rule is Traefik v3 regex syntax; v2's
# {subdomain:...} form matches nothing on v3.
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

echo "==> [1/6] starting submcp-prod-next (probe port 12009)"
docker rm -f submcp-prod-next 2>/dev/null || true
docker run -d --name submcp-prod-next --restart unless-stopped \
  --network uy2gf2yhgu9cqi16y69is4ni --network shared \
  -p 127.0.0.1:12009:12008 \
  -e POSTGRES_HOST="$POSTGRES_HOST" -e POSTGRES_PORT="$POSTGRES_PORT" \
  -e POSTGRES_USER="$POSTGRES_USER" \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  -e POSTGRES_DB="$POSTGRES_DB" \
  -e LISTEN_ADDR=:12008 \
  -e TENANT_BASE_HOST="$TENANT_BASE_HOST" \
  -e TRIAL_DAILY_LIMIT="$TRIAL_DAILY_LIMIT" \
  "${ARGS[@]}" \
  "$IMAGE"

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

echo "==> [5/6] promoting next -> prod with host port 12008 (Tailscale)"
docker rm -f submcp-prod-next 2>/dev/null || true
docker run -d --name submcp-prod --restart unless-stopped \
  --network uy2gf2yhgu9cqi16y69is4ni --network shared \
  -p 127.0.0.1:12008:12008 \
  -e POSTGRES_HOST="$POSTGRES_HOST" -e POSTGRES_PORT="$POSTGRES_PORT" \
  -e POSTGRES_USER="$POSTGRES_USER" \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  -e POSTGRES_DB="$POSTGRES_DB" \
  -e LISTEN_ADDR=:12008 \
  -e TENANT_BASE_HOST="$TENANT_BASE_HOST" \
  -e TRIAL_DAILY_LIMIT="$TRIAL_DAILY_LIMIT" \
  "${PROD_ARGS[@]}" \
  "$IMAGE"

echo "==> [6/6] verifying all entry points"
for i in $(seq 1 30); do
  if curl -sf -o /dev/null -m 3 http://127.0.0.1:12008/health; then
    echo "    host health OK (${i}s)"
    break
  fi
  [ "$i" = 30 ] && { echo "ERROR: prod never healthy" >&2; exit 1; }
  sleep 1
done
curl -sf -o /dev/null -m 8 https://mcp.subimpact.net/health && echo "    public OK"
curl -sf -o /dev/null -m 8 https://vmi3274017-vps.tailab0a04.ts.net:12008/health && echo "    tailscale OK"
# Tenant wildcard: the cert may still be issuing (DNS-01 takes a minute or
# two). Warn, do not fail; re-check with a strict curl once it settles.
curl -sf -o /dev/null -m 8 https://subimpact.mcp.subimpact.net/health && echo "    tenant host OK" \
  || echo "WARN: tenant host not serving yet (wildcard cert may still be issuing)" >&2

echo "==> done. rollback: ./scripts/deploy-blue-green.sh submcp:prev"
