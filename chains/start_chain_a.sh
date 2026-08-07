#!/usr/bin/env bash
# Chain A: local Anvil instance, port 8545, chain id 31337.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p logs
anvil --port 8545 --chain-id 31337 --block-time 2 > logs/chain_a.log 2>&1 &
echo "Chain A started (PID $!), logs at chains/logs/chain_a.log"
