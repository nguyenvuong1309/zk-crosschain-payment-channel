#!/usr/bin/env -S npx tsx
// Thin CLI wrapper around build_channel_state_input.ts for prove_and_export.sh.
// Usage: npx tsx build_ffi_input.ts <contractAddress> <chainId> <channelId>
import { buildInput } from "../input_gen/build_channel_state_input";

async function main() {
  const [, , contractAddressArg, chainIdArg, channelIdArg] = process.argv;
  if (!contractAddressArg || !chainIdArg || !channelIdArg) {
    throw new Error("usage: build_ffi_input.ts <contractAddress> <chainId> <channelId>");
  }

  const input = await buildInput({
    channelId: BigInt(channelIdArg),
    contractAddress: BigInt(contractAddressArg),
    chainId: BigInt(chainIdArg),
    initBalanceA: 1_000_000n,
    initBalanceB: 1_000_000n,
  });

  console.log(JSON.stringify(input));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
