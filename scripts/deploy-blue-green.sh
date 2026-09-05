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
# Rollback: docker start <old-image> is not needed — the previous image
# tag (submcp:prod) is overwritten by the build, so keep the old image
# tagged submcp:prev before deploying (see build step in deploy.sh).
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

IMAGE="${1:-submcp:prod}"

# Tag the current image as prev for rollback (if it exists).
if docker image inspect submcp:prod >/dev/null 2>&1; then
  docker tag submcp:prod submcp:prev 2>/dev/null || true
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
)

ARGS=()
for l in "${LABELS[@]}"; do
  ARGS+=(--label "$l")
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
if ! curl -sf -m 8 https://mcp.subimpact.net/ | grep -q "submcp - a lightweight MCP gateway"; then
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
  "${ARGS[@]//submcp-prod-next/submcp-prod}" \
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

echo "==> done. rollback: docker run with submcp:prev (see start-prod.sh)"
