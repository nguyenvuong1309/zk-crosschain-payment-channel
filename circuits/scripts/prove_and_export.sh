#!/usr/bin/env bash
# Generates a REAL Groth16 proof for channel_state.circom, bound to a
# specific deployed PaymentChannel contract address + chain id, printed as
# JSON on stdout. Invoked via Foundry's `vm.ffi` (see
# contracts/test/ChannelStateProof.t.sol) so the proof's domain separator
# always matches whatever address Forge actually deployed the contract at.
#
# Deliberately shells out to the CLI wasm witness calculator + `snarkjs
# groth16 prove` (each takes seconds) rather than snarkjs's JS
# `groth16.fullProve` API, which was observed to take ~20 minutes wall clock
# in this environment for reasons not fully diagnosed (near-zero CPU time
# while "running" — looks like some async wait pathology in that API, not
# genuine compute). This script's two-CLI-process pipeline matches exactly
# what was already proven fast during Milestone 2's manual proving run.
#
# Usage: prove_and_export.sh <contractAddress> <chainId> <channelId>

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

"$TSX" "$SCRIPT_DIR/build_ffi_input.ts" "$CONTRACT_ADDRESS" "$CHAIN_ID" "$CHANNEL_ID" > "$WORKDIR/input.json"

# generate_witness.js is circom-generated output (not ours) — stays plain JS.
node "$BUILD_DIR/channel_state_js/generate_witness.js" \
  "$BUILD_DIR/channel_state_js/channel_state.wasm" \
  "$WORKDIR/input.json" \
  "$WORKDIR/witness.wtns" >&2

npx --prefix "$CIRCUITS_DIR" snarkjs groth16 prove \
  "$BUILD_DIR/channel_state_final_v2.zkey" \
  "$WORKDIR/witness.wtns" \
  "$WORKDIR/proof.json" \
  "$WORKDIR/public.json" >&2

"$TSX" "$SCRIPT_DIR/format_ffi_output.ts" "$WORKDIR/proof.json" "$WORKDIR/public.json"
