#!/usr/bin/env node
// Thin CLI wrapper around build_channel_state_input.js for prove_and_export.sh.
// Usage: node build_ffi_input.js <contractAddress> <chainId> <channelId>
const { buildInput } = require("../input_gen/build_channel_state_input");

async function main() {
  const [, , contractAddressArg, chainIdArg, channelIdArg] = process.argv;
  if (!contractAddressArg || !chainIdArg || !channelIdArg) {
    throw new Error("usage: build_ffi_input.js <contractAddress> <chainId> <channelId>");
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
