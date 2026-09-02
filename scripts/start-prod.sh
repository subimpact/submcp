#!/bin/bash
# Start submcp-prod with Traefik labels for mcp.subimpact.net
#
# Credentials come from environment variables (or a local .env.prod file
# that is gitignored). NEVER hardcode secrets in this script.
set -e

# Load local secrets if present (gitignored; see .gitignore)
if [ -f "$(dirname "$0")/../.env.prod" ]; then
  set -a
  # shellcheck disable=SC1091
  source "$(dirname "$0")/../.env.prod"
  set +a
fi

# Required secrets (fail fast if missing)
: "${POSTGRES_USER:?POSTGRES_USER must be set (see .env.prod.example)}"
: "${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set (see .env.prod.example)}"
: "${POSTGRES_DB:=metamcp_db}"
: "${POSTGRES_HOST:=postgres}"
: "${POSTGRES_PORT:=5432}"

LABELS=(
  "traefik.docker.network=uy2gf2yhgu9cqi16y69is4ni"
  "traefik.enable=true"
  "traefik.http.middlewares.gzip.compress=true"
  "traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https"
  "traefik.http.routers.http-0-submcp-prod.entryPoints=http"
  "traefik.http.routers.http-0-submcp-prod.middlewares=redirect-to-https"
  "traefik.http.routers.http-0-submcp-prod.rule=Host(\`mcp.subimpact.net\`) && PathPrefix(\`/\`)"
  "traefik.http.routers.http-0-submcp-prod.service=http-0-submcp-prod"
  "traefik.http.routers.https-0-submcp-prod.entryPoints=https"
  "traefik.http.routers.https-0-submcp-prod.middlewares=gzip"
  "traefik.http.routers.https-0-submcp-prod.rule=Host(\`mcp.subimpact.net\`) && PathPrefix(\`/\`)"
  "traefik.http.routers.https-0-submcp-prod.service=https-0-submcp-prod"
  "traefik.http.routers.https-0-submcp-prod.tls=true"
  "traefik.http.routers.https-0-submcp-prod.tls.certresolver=letsencrypt"
  "traefik.http.services.http-0-submcp-prod.loadbalancer.server.port=12008"
  "traefik.http.services.https-0-submcp-prod.loadbalancer.server.port=12008"
)

ARGS=()
for l in "${LABELS[@]}"; do
  ARGS+=(--label "$l")
done

docker rm -f submcp-prod 2>/dev/null || true

docker run -d --name submcp-prod --restart unless-stopped \
  --network uy2gf2yhgu9cqi16y69is4ni --network shared \
  -p 127.0.0.1:12008:12008 \
  -e POSTGRES_HOST="$POSTGRES_HOST" -e POSTGRES_PORT="$POSTGRES_PORT" \
  -e POSTGRES_USER="$POSTGRES_USER" \
  -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" \
  -e POSTGRES_DB="$POSTGRES_DB" \
  -e LISTEN_ADDR=:12008 \
  "${ARGS[@]}" \
  submcp:prod

echo "started submcp-prod"
