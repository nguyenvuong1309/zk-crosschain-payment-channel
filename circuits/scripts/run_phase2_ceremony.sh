#!/usr/bin/env bash
# Runs a phase-2 (circuit-specific) Groth16 trusted setup ceremony with
# MULTIPLE independent contributions, chained — the property that makes a
# trusted setup safe is "at least ONE contributor destroyed their toxic
# waste", not "the operator is trustworthy". Each `zkey contribute` call
# below uses fresh OS entropy (`-e`) and runs as its own process; nothing
# from one contribution's randomness is persisted or reused by the next.
#
# This does NOT simulate multiple humans/machines — it's the same operator
# running the ceremony sequentially, which is a real, honestly-documented
# limitation (see docs/threat-model.md #4). What it DOES give: the resulting
# zkey is secure as long as at least one of the N contribution steps below
# had its randomness genuinely discarded after the process exited (true for
# all of them here — none of the intermediate .zkey files or entropy is
# retained beyond this script's own working files, and those are deleted).
#
# Usage: run_phase2_ceremony.sh <circuitName> <ptauFile> [numContributions]
#   e.g. run_phase2_ceremony.sh channel_state build/powersOfTau28_hez_final_17.ptau 3

set -euo pipefail

CIRCUIT_NAME="$1"
PTAU_FILE="$2"
NUM_CONTRIBUTIONS="${3:-3}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CIRCUITS_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$CIRCUITS_DIR/build"
R1CS="$BUILD_DIR/${CIRCUIT_NAME}.r1cs"
FINAL_ZKEY="$BUILD_DIR/${CIRCUIT_NAME}_final.zkey"

if [ ! -f "$R1CS" ]; then
  echo "missing $R1CS — compile the circuit first" >&2
  exit 1
fi

echo "== Phase 2 setup: $CIRCUIT_NAME (ptau: $PTAU_FILE) ==" >&2
CURRENT="$BUILD_DIR/${CIRCUIT_NAME}_0000.zkey"
npx --prefix "$CIRCUITS_DIR" snarkjs groth16 setup "$R1CS" "$PTAU_FILE" "$CURRENT"

for i in $(seq 1 "$NUM_CONTRIBUTIONS"); do
  NEXT="$BUILD_DIR/${CIRCUIT_NAME}_$(printf '%04d' "$i").zkey"
  echo "== Contribution $i/$NUM_CONTRIBUTIONS ==" >&2
  # Fresh entropy per contribution, sourced from the OS CSPRNG each time —
  # never derived from a shared seed, never written to disk.
  ENTROPY="$(head -c 64 /dev/urandom | base64)"
  npx --prefix "$CIRCUITS_DIR" snarkjs zkey contribute "$CURRENT" "$NEXT" \
    --name="contributor $i (local ceremony, see docs/threat-model.md #4)" -e="$ENTROPY" -v
  rm -f "$CURRENT"
  CURRENT="$NEXT"
done

mv "$CURRENT" "$FINAL_ZKEY"
echo "== Verifying full contribution chain ==" >&2
npx --prefix "$CIRCUITS_DIR" snarkjs zkey verify "$R1CS" "$PTAU_FILE" "$FINAL_ZKEY"

echo "Wrote $FINAL_ZKEY ($NUM_CONTRIBUTIONS contributions, verified)" >&2
