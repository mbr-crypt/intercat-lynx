#!/usr/bin/env bash
# InterCat Lynx - creates the .env file for docker compose.
#
#   ./scripts/init-env.sh                       address is detected, plain HTTP
#   ./scripts/init-env.sh http://192.168.1.50   explicit address
#   ./scripts/init-env.sh https://lynx.example.org --https
#
# Options:
#   --https   use the HTTPS nginx configuration. If nginx/ssl/nginx.crt and
#             nginx.key do not exist yet, a self-signed pair is created
#             (browsers warn about it - fine for tests, use a real certificate
#             for production).
#   --force   replace an existing .env (a backup .env.bak is kept)
#
# The script fills in random values for POSTGRES_PASSWORD, SECRET_KEY,
# CSRF_SECRET_KEY and SETUP_TOKEN. It never prints the secrets.
set -euo pipefail

cd "$(dirname "$0")/.."

URL=""
HTTPS=0
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --https) HTTPS=1 ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    http://*|https://*) URL="${arg%/}" ;;
    *) echo "Unknown argument: $arg (see --help)" >&2; exit 2 ;;
  esac
done

if [ ! -f .env.example ]; then
  echo "Run this script inside the InterCat Lynx folder (.env.example not found)." >&2
  exit 1
fi

if [ -f .env ] && [ "$FORCE" -ne 1 ]; then
  echo ".env exists already - nothing changed." >&2
  echo "Use --force to replace it (a backup .env.bak is kept)." >&2
  echo "Careful: new secrets do not fit an existing database. If the stack ran" >&2
  echo "before, either keep the old .env or start fresh: docker compose down -v" >&2
  exit 1
fi

# random value of N characters, only A-Z a-z 0-9 - _
random() {
  local n="$1" out=""
  if command -v openssl >/dev/null 2>&1; then
    out="$(openssl rand -base64 $((n * 2)) | tr '+/' '-_' | tr -d '=\n')"
  else
    out="$(head -c $((n * 3)) /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
  fi
  printf '%s' "${out:0:n}"
}

# replace "KEY=..." in .env (works with any characters in the value)
set_var() {
  local key="$1" value="$2" tmp
  tmp="$(mktemp)"
  awk -v k="$key" -v v="$value" 'BEGIN{FS=OFS="="}
    $1==k && !done {print k "=" v; done=1; next} {print}
    END{if(!done) print k "=" v}' .env >"$tmp"
  cat "$tmp" >.env
  rm -f "$tmp"
}

if [ -z "$URL" ]; then
  ip=""
  if command -v hostname >/dev/null 2>&1; then
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || true
  fi
  scheme="http"; [ "$HTTPS" -eq 1 ] && scheme="https"
  URL="${scheme}://${ip:-localhost}"
fi

[ -f .env ] && cp .env .env.bak
cp .env.example .env
chmod 600 .env

set_var POSTGRES_PASSWORD "$(random 32)"
set_var SECRET_KEY "$(random 64)"
set_var CSRF_SECRET_KEY "$(random 48)"
set_var SETUP_TOKEN "$(random 32)"
set_var PUBLIC_URL "$URL"
set_var ALLOWED_ORIGINS "$URL"

if [ "$HTTPS" -eq 1 ]; then
  set_var NGINX_CONF "./nginx/nginx.conf"
  mkdir -p nginx/ssl
  if [ ! -f nginx/ssl/nginx.crt ] || [ ! -f nginx/ssl/nginx.key ]; then
    if ! command -v openssl >/dev/null 2>&1; then
      echo "openssl is needed to create the test certificate (sudo apt install openssl)." >&2
      exit 1
    fi
    host="${URL#*://}"; host="${host%%[:/]*}"
    # An IP address needs a different subjectAltName type than a name
    if [[ "$host" =~ ^[0-9.]+$ ]]; then san="IP:${host}"; else san="DNS:${host}"; fi
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
      -keyout nginx/ssl/nginx.key -out nginx/ssl/nginx.crt \
      -subj "/CN=${host}" -addext "subjectAltName=${san}" >/dev/null 2>&1
    chmod 600 nginx/ssl/nginx.key
    echo "Created a self-signed certificate for ${host} (valid 365 days)."
  fi
fi

setup_token="$(awk -F= '$1=="SETUP_TOKEN"{print $2}' .env)"
cat <<MSG

.env created.

  Address:      ${URL}
  Web server:   $([ "$HTTPS" -eq 1 ] && echo "HTTPS (self-signed unless you replaced nginx/ssl/*)" || echo "plain HTTP")
  Setup token:  stored in .env as SETUP_TOKEN (the setup assistant asks for it)

Next:
  docker compose up -d --build
  docker compose ps            # wait until backend shows "healthy"
  then open ${URL}

MSG
unset setup_token
