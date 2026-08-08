#!/usr/bin/env bash
# Same pipeline as prove_and_export.sh, but for a CONTINUATION proof (see
# build_ffi_input_continuation.ts / channel_state.circom's "Chaining" doc
# comment) — one that anchors to a PRIOR proof's committed final state
# instead of the channel's genesis deposits.
#
# Usage: prove_and_export_continuation.sh <contractAddress> <chainId> <channelId>

set -euo pipefail

CONTRACT_ADDRESS="$1"
CHAIN_ID="$2"
CHANNEL_ID="$3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$CIRCUITS_DIR/build"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

TSX="$CIRCUITS_DIR/node_modules/.bin/tsx"

"$TSX" "$SCRIPT_DIR/build_ffi_input_continuation.ts" "$CONTRACT_ADDRESS" "$CHAIN_ID" "$CHANNEL_ID" > "$WORKDIR/input.json"

# generate_witness.js is circom-generated output (not ours) — stays plain JS.
node "$BUILD_DIR/channel_state_js/generate_witness.js" \
  "$BUILD_DIR/channel_state_js/channel_state.wasm" \
  "$WORKDIR/input.json" \
  "$WORKDIR/witness.wtns" >&2

npx --prefix "$CIRCUITS_DIR" snarkjs groth16 prove \
  "$BUILD_DIR/channel_state_final.zkey" \
  "$WORKDIR/witness.wtns" \
  "$WORKDIR/proof.json" \
  "$WORKDIR/public.json" >&2

"$TSX" "$SCRIPT_DIR/format_ffi_output.ts" "$WORKDIR/proof.json" "$WORKDIR/public.json"
