#!/usr/bin/env bash
# InterCat Lynx - update an installed stack to the newest version.
#
#   ./deploy.sh              pull, rebuild, restart
#   ./deploy.sh --no-cache   same, but rebuild the images from scratch
#
# First installation: see QUICK_START.md (./scripts/init-env.sh, then
# docker compose up -d --build). This script does not create the .env.
# The database schema is upgraded by the backend itself when it starts.
set -euo pipefail

cd "$(dirname "$0")"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}✓${NC} $*"; }
fail() { echo -e "${RED}✗ $*${NC}" >&2; exit 1; }

BUILD_ARGS=()
[ "${1:-}" = "--no-cache" ] && BUILD_ARGS+=(--no-cache)

[ -f .env ] || fail ".env not found. Run ./scripts/init-env.sh first (see QUICK_START.md)."
docker compose version >/dev/null 2>&1 || fail "The Docker Compose plugin is missing (docker compose version)."

# Compose checks that the required values (SECRET_KEY, POSTGRES_PASSWORD) are set.
# .env is not sourced here: values with special characters would break the shell.
docker compose config -q || fail "docker-compose.yml or .env is invalid (see message above)."
ok "Configuration is valid"

echo "📥 Getting the newest code..."
git pull --ff-only

echo "🔨 Building images..."
docker compose build "${BUILD_ARGS[@]}"

echo "🚀 Starting (waits until the services are healthy)..."
docker compose up -d --wait --wait-timeout 300 || {
    echo -e "${RED}A service did not become healthy:${NC}" >&2
    docker compose ps >&2
    docker compose logs --tail=40 backend >&2
    exit 1
}
ok "All services are up"

HTTP_PORT="$(grep -E '^HTTP_PORT=' .env | tail -n1 | cut -d= -f2- | tr -d '[:space:]')"
HTTP_PORT="${HTTP_PORT:-80}"
if curl -fsS "http://localhost:${HTTP_PORT}/health" >/dev/null 2>&1; then
    ok "API answers through nginx"
else
    # With the HTTPS configuration port 80 only redirects, but /health stays plain
    echo -e "${YELLOW}⚠ http://localhost:${HTTP_PORT}/health did not answer. Check: docker compose logs nginx${NC}"
fi

echo
docker compose ps
echo
echo "Logs: docker compose logs -f backend      Stop: docker compose down"
