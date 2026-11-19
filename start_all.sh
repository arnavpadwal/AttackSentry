#!/usr/bin/env bash
# AttackSentry unified dev startup.
# Starts llama.cpp (OpenAI-compatible), the backend, and the Vite dashboard.
set -Eeuo pipefail

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FRONTEND_DIR="$BASE_DIR/UI/frontend"
SENTRY_DIR="$BASE_DIR/Sentry"
ENV_FILE="$SENTRY_DIR/.env"

if [[ -x "$BASE_DIR/.venv/bin/python" ]]; then
    VENV_PYTHON="$BASE_DIR/.venv/bin/python"
else
    VENV_PYTHON="$(command -v python3)"
fi

port_busy() { (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }
env_value() { sed -n "s/^$1=//p" "$ENV_FILE" | tail -n 1; }

if [[ ! -f "$ENV_FILE" ]]; then
    echo "No Sentry/.env found — generating local credentials…"
    "$VENV_PYTHON" "$BASE_DIR/scripts/gen_secrets.py" >/dev/null
fi
if [[ ! -x "$FRONTEND_DIR/node_modules/.bin/vite" ]]; then
    echo "Frontend dependencies are missing. Run: (cd UI/frontend && npm install)"
    exit 1
fi

ADMIN_USER="$(env_value SENTRY_BOOTSTRAP_ADMIN_USERNAME)"
ADMIN_PASS="$(env_value SENTRY_BOOTSTRAP_ADMIN_PASSWORD)"
ADMIN_USER="${ADMIN_USER:-admin}"

for port in 8000 5173; do
    if port_busy "$port"; then
        echo "Port $port is already in use. Stop the existing AttackSentry stack, then retry."
        exit 1
    fi
done

LLAMA_PID=""
BACKEND_PID=""
FRONTEND_PID=""
LLM_PORT=""
LLM_ALIAS="$(env_value SENTRY_LLM_MODEL)"
[[ -n "$LLM_ALIAS" && "$LLM_ALIAS" != "default" ]] || LLM_ALIAS="qwen3.5-2b"

cleanup() {
    trap - INT TERM
    echo ""
    echo "Stopping AttackSentry…"
    for pid in "$FRONTEND_PID" "$BACKEND_PID" "$LLAMA_PID"; do
        [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    exit 0
}
trap cleanup INT TERM

echo "========================================"
echo " Starting AttackSentry Platform"
echo "========================================"

# 1. Local model server. Prefer an already-running OpenAI-compatible server
# (for example the `llm` CLI), then fall back to launching bundled llama.cpp.
LLM_BASE="$(env_value SENTRY_LLM_BASE_URL)"
LLM_BASE="${LLM_BASE:-http://127.0.0.1:8081}"
LLAMA_BIN="${LLAMA_SERVER:-$(command -v llama-server || true)}"
LLAMA_MODEL="${SENTRY_LLAMA_MODEL:-$HOME/.lmstudio/models/lmstudio-community/Qwen3.5-2B-GGUF/Qwen3.5-2B-Q4_K_M.gguf}"
if curl -fsS --max-time 3 "$LLM_BASE/v1/models" >/dev/null 2>&1; then
    LLM_PORT="${LLM_BASE##*:}"
    echo "[1/3] Using local model server at $LLM_BASE (model: $LLM_ALIAS)"
elif [[ -n "$LLAMA_BIN" && -f "$LLAMA_MODEL" ]]; then
    for candidate in "${SENTRY_LLAMA_PORT:-1234}" 1234 1235 1236 1237 1238; do
        if ! port_busy "$candidate"; then LLM_PORT="$candidate"; break; fi
    done
    if [[ -n "$LLM_PORT" ]]; then
        echo "[1/3] Starting llama.cpp on 127.0.0.1:$LLM_PORT…"
        "$LLAMA_BIN" -m "$LLAMA_MODEL" --alias "$LLM_ALIAS" \
            --host 127.0.0.1 --port "$LLM_PORT" \
            -c "${SENTRY_LLAMA_CTX:-8192}" -ngl "${SENTRY_LLAMA_NGL:-99}" \
            >/tmp/attacksentry-llama.log 2>&1 &
        LLAMA_PID=$!
        for _ in $(seq 1 60); do
            curl -fsS "http://127.0.0.1:$LLM_PORT/v1/models" >/dev/null 2>&1 && break
            sleep 1
        done
        if ! curl -fsS "http://127.0.0.1:$LLM_PORT/v1/models" >/dev/null 2>&1; then
            echo "      llama.cpp did not become ready — see /tmp/attacksentry-llama.log"
            kill "$LLAMA_PID" 2>/dev/null || true
            LLAMA_PID=""
            LLM_PORT=""
        fi
    else
        echo "[1/3] No free port for llama.cpp — AI triage will use fallback playbooks."
    fi
else
    echo "[1/3] No local model server and llama-server/model not found — AI triage will use fallback playbooks."
    echo "      Start one with the 'llm' CLI, or set SENTRY_LLAMA_MODEL=/path/to/model.gguf."
fi

# 2. Backend (core + API)
echo "[2/3] Starting backend…"
# If a local NATS bus is running and the developer has not configured one,
# connect the core automatically using the compose credentials.
if [[ -z "${SENTRY_NATS_URL:-}" && -f "$BASE_DIR/deploy/docker-compose/.env" ]]; then
    NATS_USER="$(sed -n 's/^NATS_USER=//p' "$BASE_DIR/deploy/docker-compose/.env" | tail -n 1)"
    NATS_PASS="$(sed -n 's/^NATS_PASSWORD=//p' "$BASE_DIR/deploy/docker-compose/.env" | tail -n 1)"
    if [[ -n "$NATS_PASS" ]] && (exec 3<>/dev/tcp/127.0.0.1/4222) 2>/dev/null; then
        export SENTRY_NATS_URL="nats://${NATS_USER:-attacksentry}:${NATS_PASS}@127.0.0.1:4222"
        echo "      NATS ingestion enabled on 127.0.0.1:4222"
    fi
fi
cd "$SENTRY_DIR"
echo "      Applying database migrations…"
if ! "$VENV_PYTHON" -m alembic upgrade head; then
    echo "Database migration failed. Backend was not started."
    exit 1
fi

# Persist the llama.cpp endpoint so the Settings page and the runtime agree.
if [[ -n "$LLM_PORT" ]]; then
    DB_URL="$(env_value SENTRY_DATABASE_URL)"
    if [[ "$DB_URL" == sqlite* ]]; then
        DB_PATH="${DB_URL#*///}"
        [[ "$DB_PATH" = /* ]] || DB_PATH="$SENTRY_DIR/${DB_PATH#./}"
        if [[ -f "$DB_PATH" ]]; then
            DB_PATH="$DB_PATH" LLM_PORT="$LLM_PORT" LLM_ALIAS="$LLM_ALIAS" "$VENV_PYTHON" - <<'PY'
import json, os, sqlite3
db = os.environ["DB_PATH"]
port = os.environ["LLM_PORT"]
alias = os.environ["LLM_ALIAS"]
con = sqlite3.connect(db)
row = con.execute("select value from system_config where key='runtime_settings'").fetchone()
cfg = json.loads(row[0]) if row and row[0] else {}
cfg.update({
    "llm_provider": "openai",
    "llm_base_url": f"http://127.0.0.1:{port}",
    "llm_model": alias,
})
if row:
    con.execute("update system_config set value=? where key='runtime_settings'", (json.dumps(cfg),))
else:
    con.execute("insert into system_config (key, value) values ('runtime_settings', ?)", (json.dumps(cfg),))
con.commit()
con.close()
PY
            echo "      LLM configured: llama.cpp ($LLM_ALIAS) on 127.0.0.1:$LLM_PORT"
        fi
    else
        echo "      Non-SQLite database: set AI provider 'openai' to http://127.0.0.1:$LLM_PORT in Settings."
    fi
    export SENTRY_LLM_PROVIDER=openai
    export SENTRY_LLM_BASE_URL="http://127.0.0.1:$LLM_PORT"
    export SENTRY_LLM_MODEL="$LLM_ALIAS"
fi

SENTRY_COOKIE_SECURE="${SENTRY_COOKIE_SECURE:-false}" \
SENTRY_ENVIRONMENT="${SENTRY_ENVIRONMENT:-development}" \
"$VENV_PYTHON" -m sentry &
BACKEND_PID=$!

# 3. Dashboard (Vite dev)
echo "[3/3] Starting dashboard…"
cd "$FRONTEND_DIR"
npm run dev -- --host 127.0.0.1 &
FRONTEND_PID=$!

BACKEND_READY=0
for _ in $(seq 1 60); do
    if curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then
        BACKEND_READY=1
        break
    fi
    kill -0 "$BACKEND_PID" 2>/dev/null || break
    sleep 1
done
if [[ "$BACKEND_READY" -ne 1 ]]; then
    echo "Backend did not become ready. Check the log above."
    kill "$FRONTEND_PID" "$BACKEND_PID" "$LLAMA_PID" 2>/dev/null || true
    exit 1
fi

if [[ -n "$LLM_PORT" ]]; then
    LLM_DESC="llama.cpp · $LLM_ALIAS · 127.0.0.1:$LLM_PORT"
else
    LLM_DESC="unavailable (deterministic fallback)"
fi

echo "========================================"
echo " AttackSentry is running"
echo "----------------------------------------"
echo " Dashboard : http://localhost:5173"
echo " API docs  : http://localhost:8000/api/docs"
echo " Username  : $ADMIN_USER"
if [[ -n "$ADMIN_PASS" ]]; then
    echo " Password  : $ADMIN_PASS"
else
    echo " Password  : not set in Sentry/.env"
fi
echo " AI triage : $LLM_DESC"
echo "----------------------------------------"
echo " Simulate  : ./scripts/attack_sim.sh"
echo " Stop      : Ctrl+C"
echo "========================================"

wait
