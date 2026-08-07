#!/usr/bin/env -S npx tsx
// Thin CLI wrapper around build_consensus_proof_input.ts for
// prove_and_export_consensus.sh. Usage:
//   npx tsx build_ffi_input_consensus.ts <chainId> <blockNumber> <stateRoot>
import { buildInput } from "../input_gen/build_consensus_proof_input";

async function main() {
  const [, , chainIdArg, blockNumberArg, stateRootArg] = process.argv;
  if (!chainIdArg || !blockNumberArg || !stateRootArg) {
    throw new Error("usage: build_ffi_input_consensus.ts <chainId> <blockNumber> <stateRoot>");
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
