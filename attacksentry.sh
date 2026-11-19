#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_DIR="$ROOT_DIR/deploy/docker-compose"
ENV_FILE="$COMPOSE_DIR/.env"
ACTION="${1:-start}"

require_docker() {
  if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "AttackSentry requires Docker Engine 24+ with Docker Compose v2."
    echo "Install Docker, then run this command again."
    exit 1
  fi
}

ensure_config() {
  if [[ ! -f "$ENV_FILE" ]]; then
    echo "Creating secure first-run configuration..."
    python3 "$ROOT_DIR/scripts/gen_secrets.py"
    echo
    echo "Save the admin password shown above in your password manager."
  elif ! grep -q '^NATS_PASSWORD=' "$ENV_FILE"; then
    # Upgrade legacy configurations without replacing database/JWT secrets.
    local nats_password
    nats_password="$(python3 -c 'import secrets; print(secrets.token_hex(24))')"
    {
      echo
      grep -q '^NATS_USER=' "$ENV_FILE" || echo 'NATS_USER=attacksentry'
      echo "NATS_PASSWORD=$nats_password"
      grep -q '^NATS_BIND_HOST=' "$ENV_FILE" || echo 'NATS_BIND_HOST=127.0.0.1'
    } >> "$ENV_FILE"
    echo "Added NATS authentication to the existing configuration; existing secrets were preserved."
  fi
}

compose() {
  docker compose --project-directory "$COMPOSE_DIR" --env-file "$ENV_FILE" -f "$COMPOSE_DIR/docker-compose.yml" "$@"
}

wait_until_ready() {
  local console_port
  console_port="$(sed -n 's/^FRONTEND_PORT=//p' "$ENV_FILE" | tail -n 1)"
  console_port="${console_port:-8080}"
  echo "Waiting for the security console..."
  for _attempt in {1..60}; do
    if curl --silent --fail "http://127.0.0.1:${console_port}/readyz" >/dev/null 2>&1; then
      echo "AttackSentry is ready: http://localhost:${console_port}"
      return 0
    fi
    sleep 2
  done
  echo "The platform did not become ready in time. Run: ./attacksentry.sh logs"
  return 1
}

require_docker

case "$ACTION" in
  start|up)
    ensure_config
    compose up -d --build
    wait_until_ready
    ;;
  stop|down)
    compose down
    ;;
  restart)
    ensure_config
    compose restart
    wait_until_ready
    ;;
  status)
    compose ps
    ;;
  logs)
    if [[ -n "${2:-}" ]]; then compose logs --follow --tail=200 "$2"; else compose logs --follow --tail=200; fi
    ;;
  update)
    ensure_config
    compose pull
    compose up -d --build
    wait_until_ready
    ;;
  doctor)
    ensure_config
    echo "Docker: $(docker --version)"
    echo "Compose: $(docker compose version --short)"
    compose config --quiet
    echo "Configuration: valid"
    compose ps
    ;;
  *)
    echo "Usage: ./attacksentry.sh {start|stop|restart|status|logs [service]|update|doctor}"
    exit 2
    ;;
esac
