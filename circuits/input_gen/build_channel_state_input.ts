// Shared witness-building logic for channel_state.circom, used both by the
// standalone CLI script (generate_channel_state_input.ts) and by
// scripts/build_ffi_input.ts (invoked via Foundry FFI to bind a proof to a
// specific deployed PaymentChannel address/chainid at test time).

import * as circomlibjs from "circomlibjs";

export const DEFAULT_PRIV_KEY_A = Buffer.from("0001020304050607080900010203040506070809000102030405060708aaaa", "hex");
export const DEFAULT_PRIV_KEY_B = Buffer.from("0001020304050607080900010203040506070809000102030405060708bbbb", "hex");

export interface Update {
  nonce: bigint;
  balanceA: bigint;
  balanceB: bigint;
}

// 4 off-chain updates: A pays B a bit more each time. Nonces need not be
// consecutive, only strictly increasing.
export const DEFAULT_UPDATES: Update[] = [
  { nonce: 1n, balanceA: 900_000n, balanceB: 1_100_000n },
  { nonce: 2n, balanceA: 750_000n, balanceB: 1_250_000n },
  { nonce: 5n, balanceA: 600_000n, balanceB: 1_400_000n },
  { nonce: 6n, balanceA: 400_000n, balanceB: 1_600_000n },
];

// Fixed demo blinding factor — arbitrary but deterministic, see
// BuildChannelStateInputOptions.endBlinding.
export const DEFAULT_BLINDING = 424242424242424242n;

export interface BuildChannelStateInputOptions {
  channelId: bigint;
  contractAddress: bigint;
  chainId: bigint;
  // The anchor this proof's chain starts from. For a GENESIS proof (the
  // channel's first-ever closeWithProof/challengeWithProof), pass the
  // channel's on-chain deposits with startNonce=0n and startBlinding=0n —
  // see channel_state.circom's doc comment on Chaining for why 0n is the
  // fixed, publicly-checkable anchor blinding, not a secret. For a
  // CONTINUATION proof, pass whatever a prior proof's
  // endBalanceA/B/endBlinding/outNonce were (the prover must already know
  // these to extend that proof).
  startBalanceA: bigint;
  startBalanceB: bigint;
  startNonce?: bigint; // defaults to 0n (genesis)
  startBlinding?: bigint; // defaults to 0n (genesis)
  updates?: Update[];
  privKeyA?: Buffer;
  privKeyB?: Buffer;
  // Blinds `endCommitment = Poseidon(outBalanceA, outBalanceB, endBlinding)`
  // (see channel_state.circom's doc comment) — defaults to a fixed demo
  // value so tests/scripts that need to independently recompute the
  // expected commitment (e.g. contracts/test/ChannelStateProof.t.sol) can.
  // A real prover would pick this randomly and remember it to withdraw (or
  // to generate the next chained proof) later.
  endBlinding?: bigint;
}

/// @param opts.channelId           bigint
/// @param opts.contractAddress     bigint (uint160-range) — the domain separator
/// @param opts.chainId             bigint — the domain separator
/// @param opts.startBalanceA/B     bigint — this proof's anchor state (see
///                                 BuildChannelStateInputOptions' doc comment)
/// @param opts.updates             optional override of DEFAULT_UPDATES
/// @param opts.privKeyA/B          optional override of the demo EdDSA keys
export async function buildInput(opts: BuildChannelStateInputOptions) {
  const eddsa = await circomlibjs.buildEddsa();
  const poseidon = await circomlibjs.buildPoseidon();
  const F = poseidon.F;

  const privKeyA = opts.privKeyA ?? DEFAULT_PRIV_KEY_A;
  const privKeyB = opts.privKeyB ?? DEFAULT_PRIV_KEY_B;
  const pubKeyA = eddsa.prv2pub(privKeyA);
  const pubKeyB = eddsa.prv2pub(privKeyB);

  const { channelId, contractAddress, chainId, startBalanceA, startBalanceB } = opts;
  const startNonce = opts.startNonce ?? 0n;
  const startBlinding = opts.startBlinding ?? 0n;
  const updates = opts.updates ?? DEFAULT_UPDATES;
  const totalDeposit = startBalanceA + startBalanceB;

  for (const u of updates) {
    if (u.balanceA + u.balanceB !== totalDeposit) {
      throw new Error(`conservation violated at nonce ${u.nonce}`);
    }
  }

  function signState(privKey: Buffer, u: Update) {
    // Must mirror channel_state.circom's msgHash exactly: Poseidon(6) over
    // (contractAddress, chainId, channelId, nonce, balanceA, balanceB).
    const msg = poseidon([contractAddress, chainId, channelId, u.nonce, u.balanceA, u.balanceB]);
    const sig = eddsa.signPoseidon(privKey, msg);
    return {
      S: sig.S.toString(),
      R8x: F.toObject(sig.R8[0]).toString(),
      R8y: F.toObject(sig.R8[1]).toString(),
    };
  }

  const sigA = updates.map((u) => signState(privKeyA, u));
  const sigB = updates.map((u) => signState(privKeyB, u));

  return {
    channelId: channelId.toString(),
    pubKeyAx: F.toObject(pubKeyA[0]).toString(),
    pubKeyAy: F.toObject(pubKeyA[1]).toString(),
    pubKeyBx: F.toObject(pubKeyB[0]).toString(),
    pubKeyBy: F.toObject(pubKeyB[1]).toString(),
    contractAddress: contractAddress.toString(),
    chainId: chainId.toString(),
    startNonce: startNonce.toString(),

    startBalanceA: startBalanceA.toString(),
    startBalanceB: startBalanceB.toString(),
    startBlinding: startBlinding.toString(),

    nonce: updates.map((u) => u.nonce.toString()),
    balanceA: updates.map((u) => u.balanceA.toString()),
    balanceB: updates.map((u) => u.balanceB.toString()),

    sigA_S: sigA.map((s) => s.S),
    sigA_R8x: sigA.map((s) => s.R8x),
    sigA_R8y: sigA.map((s) => s.R8y),

    sigB_S: sigB.map((s) => s.S),
    sigB_R8x: sigB.map((s) => s.R8x),
    sigB_R8y: sigB.map((s) => s.R8y),

    endBlinding: (opts.endBlinding ?? DEFAULT_BLINDING).toString(),
  };
}
