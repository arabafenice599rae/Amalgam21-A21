#!/usr/bin/env bash
# Amalgam21 — suite completa di test (nextest se disponibile, cargo test altrimenti)
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Formattazione =="
cargo fmt --all -- --check

echo "== Clippy (warning come errori) =="
cargo clippy --workspace --all-targets -- -D warnings

echo "== Test (property testing: PROPCASES casi per proprieta') =="
export PROPCASES="${PROPCASES:-256}"
if cargo nextest --version >/dev/null 2>&1; then
    cargo nextest run --workspace
else
    cargo test --workspace
fi

echo "== Bench smoke (compilazione e 1 campione) =="
cargo bench --workspace --no-run
echo "OK"
