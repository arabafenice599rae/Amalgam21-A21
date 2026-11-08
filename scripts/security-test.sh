#!/usr/bin/env bash
# Amalgam21 — controlli di sicurezza statici
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== Vulnerabilita' note (cargo-audit) =="
cargo audit

echo "== Licenze e advisory (cargo-deny) =="
cargo deny --workspace check advisories bans sources

echo "== Codice unsafe (cargo-geiger) =="
if command -v cargo-geiger >/dev/null 2>&1; then
    cargo geiger --workspace
else
    echo "AVVISO: cargo-geiger non installato (cargo install cargo-geiger)"
fi

echo "OK"
