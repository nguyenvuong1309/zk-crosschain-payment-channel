#!/usr/bin/env bash
# Chain B: local Anvil instance, port 8546, chain id 31338.
# Different block time than Chain A on purpose — real chains never share
# finality timing, and the relayer/proof design must not assume they do.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p logs
anvil --port 8546 --chain-id 31338 --block-time 3 > logs/chain_b.log 2>&1 &
echo "Chain B started (PID $!), logs at chains/logs/chain_b.log"
