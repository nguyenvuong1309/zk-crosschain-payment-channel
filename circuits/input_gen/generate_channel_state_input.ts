#!/usr/bin/env -S npx tsx
// Generates a valid witness input for channel_state.circom by simulating
// two parties (A, B) exchanging 4 signed off-chain balance updates, exactly
// as PaymentChannel.sol's off-chain protocol would in practice — except
// signed with EdDSA/Poseidon (circuit-cheap) instead of ECDSA (see PLAN.md
// section 2 for why).
//
// Usage: npx tsx input_gen/generate_channel_state_input.ts [contractAddress] [chainId] > build/input.json
//   contractAddress - hex/decimal, defaults to a dummy demo value (this
//                      script is for manual circuit exploration; for a proof
//                      that verifies against a REAL deployed PaymentChannel,
//                      use scripts/build_ffi_input.ts instead, which is what
//                      the Foundry tests use via FFI).
//   chainId          - defaults to 31337 (Anvil/Foundry default)

import { buildInput } from "./build_channel_state_input";

async function main() {
  const contractAddressArg = process.argv[2] ?? "0x1111111111111111111111111111111111111111";
  const chainIdArg = process.argv[3] ?? "31337";

  const input = await buildInput({
    channelId: 1n,
    contractAddress: BigInt(contractAddressArg),
    chainId: BigInt(chainIdArg),
    startBalanceA: 1_000_000n,
    startBalanceB: 1_000_000n,
  });

  console.log(JSON.stringify(input, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
