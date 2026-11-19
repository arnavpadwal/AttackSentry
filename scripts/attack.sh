#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="$ROOT_DIR/.venv/bin/python"
[[ -x "$PYTHON" ]] || PYTHON="$(command -v python3)"
if [[ -z "${ATTACKSENTRY_URL:-}" ]]; then
  if command -v curl >/dev/null 2>&1 && curl -fsS http://127.0.0.1:8000/healthz >/dev/null 2>&1; then
    export ATTACKSENTRY_URL=http://127.0.0.1:8000
  else
    export ATTACKSENTRY_URL=http://127.0.0.1:8080
  fi
fi

while true; do
  echo
  echo "AttackSentry safe telemetry simulator"
  echo "1) Distributed DNS reflection DDoS"
  echo "2) Port scan"
  echo "3) SSH brute force"
  echo "4) Command-and-control beacon"
  echo "5) Data exfiltration"
  echo "6) Run all scenarios"
  echo "7) Train baseline, then run all"
  echo "0) Exit"
  read -r -p "Select scenario: " choice
  case "$choice" in
    1) scenario=ddos ;;
    2) scenario=scan ;;
    3) scenario=bruteforce ;;
    4) scenario=c2 ;;
    5) scenario=exfiltration ;;
    6) scenario=all ;;
    7) "$PYTHON" "$ROOT_DIR/scripts/attack_scenarios.py" --scenario all; continue ;;
    0) exit 0 ;;
    *) echo "Invalid selection"; continue ;;
  esac
  read -r -p "Number of synthetic flows [25]: " count
  count="${count:-25}"
  [[ "$count" =~ ^[0-9]+$ ]] || { echo "Count must be a positive number"; continue; }
  "$PYTHON" "$ROOT_DIR/scripts/attack_scenarios.py" --scenario "$scenario" --count "$count" --skip-baseline
done
