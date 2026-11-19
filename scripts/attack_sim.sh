#!/usr/bin/env bash
# One-shot attack simulation against a running AttackSentry instance.
# Default: train the simulated corporate baseline, then run every known
# scenario and all three zero-day behaviours.
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT_DIR/.venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON="$(command -v python3)"
URL="${ATTACKSENTRY_URL:-http://127.0.0.1:8000}"

for _ in $(seq 1 60); do
    curl -fsS "$URL/healthz" >/dev/null 2>&1 && break
    sleep 1
done
if ! curl -fsS "$URL/healthz" >/dev/null 2>&1; then
    echo "AttackSentry is not running at $URL."
    echo "Start it first with ./start_all.sh, then rerun this script."
    exit 1
fi

if [[ $# -eq 0 ]]; then
    set -- --fresh-baseline --scenario all
fi

export ATTACKSENTRY_URL="$URL"
echo "Running attack simulation against $URL…"
exec "$PYTHON" "$ROOT_DIR/scripts/attack_scenarios.py" "$@"
