#!/usr/bin/env node
// Thin CLI wrapper around build_consensus_proof_input.js for
// prove_and_export_consensus.sh. Usage:
//   build_ffi_input_consensus.js <chainId> <blockNumber> <stateRoot>
const { buildInput } = require("../input_gen/build_consensus_proof_input");

async function main() {
  const [, , chainIdArg, blockNumberArg, stateRootArg] = process.argv;
  if (!chainIdArg || !blockNumberArg || !stateRootArg) {
    throw new Error("usage: build_ffi_input_consensus.js <chainId> <blockNumber> <stateRoot>");
  }

  const input = await buildInput({
    chainId: BigInt(chainIdArg),
    blockNumber: BigInt(blockNumberArg),
    stateRoot: BigInt(stateRootArg),
  });

  console.log(JSON.stringify(input));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
