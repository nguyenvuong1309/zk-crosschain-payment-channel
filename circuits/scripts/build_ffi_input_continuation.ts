#!/usr/bin/env -S npx tsx
// Thin CLI wrapper around build_channel_state_input.ts for
// prove_and_export_continuation.sh — a SECOND proof continuing from the
// first proof's committed final state, demonstrating chaining past
// channel_state.circom's `steps=4` per-proof limit (see its "Chaining"
// doc comment and contracts/test/ChannelStateProof.t.sol's
// test_challengeWithProof_chainsFromPriorCommitment_pastFourUpdates).
//
// Anchor values here are NOT arbitrary — they must match exactly what
// build_channel_state_input.ts's DEFAULT_UPDATES/DEFAULT_BLINDING (the
// genesis proof's fixture, used by build_ffi_input.ts) actually end at:
// nonce=6, balanceA=400_000, balanceB=1_600_000, blinding=DEFAULT_BLINDING.
//
// Usage: npx tsx build_ffi_input_continuation.ts <contractAddress> <chainId> <channelId>
import { buildInput, DEFAULT_BLINDING } from "../input_gen/build_channel_state_input";

async function main() {
  const [, , contractAddressArg, chainIdArg, channelIdArg] = process.argv;
  if (!contractAddressArg || !chainIdArg || !channelIdArg) {
    throw new Error("usage: build_ffi_input_continuation.ts <contractAddress> <chainId> <channelId>");
  }

  const input = await buildInput({
    channelId: BigInt(channelIdArg),
    contractAddress: BigInt(contractAddressArg),
    chainId: BigInt(chainIdArg),

    // Anchor: exactly where the genesis proof (build_ffi_input.ts's
    // DEFAULT_UPDATES) left off.
    startBalanceA: 400_000n,
    startBalanceB: 1_600_000n,
    startNonce: 6n,
    startBlinding: DEFAULT_BLINDING,

    // 4 MORE off-chain updates, continuing the same total deposit
    // (400_000 + 1_600_000 = 2_000_000, conserved throughout).
    updates: [
      { nonce: 7n, balanceA: 300_000n, balanceB: 1_700_000n },
      { nonce: 8n, balanceA: 250_000n, balanceB: 1_750_000n },
      { nonce: 9n, balanceA: 150_000n, balanceB: 1_850_000n },
      { nonce: 10n, balanceA: 100_000n, balanceB: 1_900_000n },
    ],
    endBlinding: DEFAULT_BLINDING,
  });

  console.log(JSON.stringify(input));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
