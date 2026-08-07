// Shared witness-building logic for consensus_proof.circom — mirrors
// build_channel_state_input.ts's shape/conventions. Used by both the
// standalone CLI script and scripts/build_ffi_input_consensus.ts (invoked
// via Foundry/relayer FFI to bind a proof to a specific chainId/blockNumber/
// stateRoot at call time).

import * as circomlibjs from "circomlibjs";

export const NUM_VALIDATORS = 5;
export const THRESHOLD = 3;

// 5 demo validator private keys — NOT a real consensus committee, see
// docs/threat-model.md #6. Deterministic/fixed (same pattern as
// build_channel_state_input.ts's DEFAULT_PRIV_KEY_A/B) so
// LightClientVerifier.sol can hardcode the corresponding public keys.
export const DEMO_VALIDATOR_PRIV_KEYS: Buffer[] = [
  Buffer.from("0001020304050607080900010203040506070809000102030405060708c001", "hex"),
  Buffer.from("0001020304050607080900010203040506070809000102030405060708c002", "hex"),
  Buffer.from("0001020304050607080900010203040506070809000102030405060708c003", "hex"),
  Buffer.from("0001020304050607080900010203040506070809000102030405060708c004", "hex"),
  Buffer.from("0001020304050607080900010203040506070809000102030405060708c005", "hex"),
];

export interface BuildConsensusProofInputOptions {
  chainId: bigint;
  blockNumber: bigint;
  stateRoot: bigint;
  participating?: bigint[];
}

/// @param opts.chainId       bigint — the chain being attested to
/// @param opts.blockNumber   bigint — monotonic, prevents replay of stale attestations
/// @param opts.stateRoot     bigint — the value being attested (e.g. a channel's final-state hash)
/// @param opts.participating optional bigint[NUM_VALIDATORS] (0n/1n) override (default: first THRESHOLD sign)
export async function buildInput(opts: BuildConsensusProofInputOptions) {
  const eddsa = await circomlibjs.buildEddsa();
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;

  const { chainId, blockNumber, stateRoot } = opts;
  const participating = opts.participating ?? DEMO_VALIDATOR_PRIV_KEYS.map((_, i) => (i < THRESHOLD ? 1n : 0n));

  const pubKeys = DEMO_VALIDATOR_PRIV_KEYS.map((prv) => eddsa.prv2pub(prv));
  const msg = poseidon([chainId, blockNumber, stateRoot]);

  const sigS: string[] = [];
  const sigR8x: string[] = [];
  const sigR8y: string[] = [];
  for (let i = 0; i < NUM_VALIDATORS; i++) {
    if (participating[i]) {
      const sig = eddsa.signPoseidon(DEMO_VALIDATOR_PRIV_KEYS[i]!, msg);
      sigS.push(sig.S.toString());
      sigR8x.push(F.toObject(sig.R8[0]).toString());
      sigR8y.push(F.toObject(sig.R8[1]).toString());
    } else {
      // EdDSAPoseidonVerifier's `enabled` flag being 0 skips the constraint
      // entirely — the (0,0,0) placeholder never needs to be a valid signature.
      sigS.push("0");
      sigR8x.push("0");
      sigR8y.push("0");
    }
  }

  return {
    chainId: chainId.toString(),
    blockNumber: blockNumber.toString(),
    stateRoot: stateRoot.toString(),
    validatorPubKeyX: pubKeys.map((p) => F.toObject(p[0]).toString()),
    validatorPubKeyY: pubKeys.map((p) => F.toObject(p[1]).toString()),
    participating: participating.map((p) => p.toString()),
    sigS,
    sigR8x,
    sigR8y,
  };
}
