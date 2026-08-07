#!/usr/bin/env bash
# Generates a REAL Groth16 proof for consensus_proof.circom, printed as JSON
# on stdout. Mirrors prove_and_export.sh's two-CLI-process pipeline (see that
# script's comment for why: the JS `groth16.fullProve` API was observed to
# be anomalously slow in this environment).
#
# Usage: prove_and_export_consensus.sh <chainId> <blockNumber> <stateRoot>

set -euo pipefail

CHAIN_ID="$1"
BLOCK_NUMBER="$2"
STATE_ROOT="$3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$CIRCUITS_DIR/build"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

node "$SCRIPT_DIR/build_ffi_input_consensus.js" "$CHAIN_ID" "$BLOCK_NUMBER" "$STATE_ROOT" > "$WORKDIR/input.json"

node "$BUILD_DIR/consensus_proof_js/generate_witness.js" \
  "$BUILD_DIR/consensus_proof_js/consensus_proof.wasm" \
  "$WORKDIR/input.json" \
  "$WORKDIR/witness.wtns" >&2

npx --prefix "$CIRCUITS_DIR" snarkjs groth16 prove \
  "$BUILD_DIR/consensus_proof_final.zkey" \
  "$WORKDIR/witness.wtns" \
  "$WORKDIR/proof.json" \
  "$WORKDIR/public.json" >&2

node "$SCRIPT_DIR/format_ffi_output.js" "$WORKDIR/proof.json" "$WORKDIR/public.json"
