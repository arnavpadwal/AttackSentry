#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-1.0.0}"
OUTPUT_DIR="$ROOT_DIR/release/AttackSentry-$VERSION"
WINDOWS_BINARY="${WINDOWS_BINARY:-$ROOT_DIR/sentry_sensor/target/x86_64-pc-windows-msvc/release/sentry_sensor.exe}"

if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  cargo build --manifest-path "$ROOT_DIR/sentry_sensor/Cargo.toml" --release
  npm --prefix "$ROOT_DIR/UI/frontend" run build
fi

if [[ ! -x "$ROOT_DIR/sentry_sensor/target/release/sentry_sensor" ]]; then
  echo "Linux sensor executable is missing. Build the sensor first."
  exit 1
fi
if [[ ! -f "$WINDOWS_BINARY" ]]; then
  echo "Windows sensor executable is missing. Run the Windows release workflow or set WINDOWS_BINARY."
  exit 1
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/sensor/linux-x86_64" "$OUTPUT_DIR/sensor/windows-x86_64" "$OUTPUT_DIR/platform" "$OUTPUT_DIR/docs"

install -m 0755 "$ROOT_DIR/sentry_sensor/target/release/sentry_sensor" "$OUTPUT_DIR/sensor/linux-x86_64/attacksentry-sensor"
install -m 0644 "$WINDOWS_BINARY" "$OUTPUT_DIR/sensor/windows-x86_64/AttackSentry-Sensor.exe"
cp "$ROOT_DIR/sentry_sensor/config.example.json" "$OUTPUT_DIR/sensor/linux-x86_64/config.example.json"
cp "$ROOT_DIR/sentry_sensor/config.example.json" "$OUTPUT_DIR/sensor/windows-x86_64/config.example.json"

cp "$ROOT_DIR/attacksentry.sh" "$ROOT_DIR/attacksentry.ps1" "$OUTPUT_DIR/platform/"
cp -R "$ROOT_DIR/deploy" "$ROOT_DIR/Sentry" "$ROOT_DIR/UI" "$ROOT_DIR/scripts" "$OUTPUT_DIR/platform/"
rm -rf "$OUTPUT_DIR/platform/Sentry/data" "$OUTPUT_DIR/platform/Sentry/.pytest_cache" "$OUTPUT_DIR/platform/UI/frontend/node_modules" "$OUTPUT_DIR/platform/UI/frontend/dist"
rm -f "$OUTPUT_DIR/platform/Sentry/.env" "$OUTPUT_DIR/platform/Sentry/attacksentry.db" "$OUTPUT_DIR/platform/deploy/docker-compose/.env"
rm -f "$OUTPUT_DIR/platform/scripts/.demo_key"
find "$OUTPUT_DIR/platform" -type d -name '__pycache__' -prune -exec rm -rf {} +
find "$OUTPUT_DIR/platform" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

cp "$ROOT_DIR/README.md" "$ROOT_DIR/LICENSE" "$OUTPUT_DIR/"

(
  cd "$OUTPUT_DIR"
  find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum
) > "$OUTPUT_DIR/SHA256SUMS"
echo "Release assembled at $OUTPUT_DIR"
