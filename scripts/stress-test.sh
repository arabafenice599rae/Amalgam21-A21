#!/usr/bin/env bash
# Amalgam21 — stress test del ledger
# Uso: scripts/stress-test.sh [TXS] [EPISODE_TXS]
set -euo pipefail
cd "$(dirname "$0")/.."

TXS="${1:-100000}"
EPISODE="${2:-100000}"

cargo run --release -p amg21-stress -- --txs "$TXS" --episode-txs "$EPISODE"
