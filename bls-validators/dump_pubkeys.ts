#!/usr/bin/env -S npx tsx
// Tiny FFI helper for contracts/test/LightClientVerifierBLSGeneral.t.sol and
// contracts/test/SSZ.t.sol — prints a flat JSON array of pubkey hex strings
// from a keys_general_*.json file, so a Foundry test can
// `vm.parseJsonBytesArray` it directly instead of parsing the full
// committee JSON shape in Solidity.
//
// Usage: npx tsx dump_pubkeys.ts <keysJsonPath> [compressed]
//   Default prints the EIP-2537 (128-byte) encoding, used by
//   LightClientVerifierBLSGeneral.sol's G1ADD precompile calls. Pass
//   "compressed" to print the standard 48-byte compressed encoding instead
//   — the format SSZ.sol / real Ethereum data uses (see
//   sync_committee_probe.ts, dump_committee_root.ts).
import fs from "fs";

const [, , keysJsonPath, mode] = process.argv;
if (!keysJsonPath) {
  console.error("usage: dump_pubkeys.ts <keysJsonPath> [compressed]");
  process.exit(1);
}

const keys = JSON.parse(fs.readFileSync(keysJsonPath, "utf8")) as {
  validators: { pubkey: string; pubkeyCompressed?: string }[];
  aggregatePubkeyCompressed?: string;
};
const field = mode === "compressed" ? "pubkeyCompressed" : "pubkey";
const pubkeys = keys.validators.map((v) => {
  const value = v[field as "pubkey" | "pubkeyCompressed"];
  if (!value) throw new Error(`validator missing "${field}" — regenerate with generate_keys_general.ts`);
  return value;
});
// Wrapped in an object (not a bare root-level array) — Foundry's
// vm.parseJsonBytesArray(json, key) expects a JSONPath key, and an empty
// path for "the whole root is the array" isn't a well-defined case across
// forge-std versions; ".pubkeys" is unambiguous. `aggregatePubkeyCompressed`
// tags along here too (rather than a separate FFI script) so Solidity tests
// never need `vm.readFile` (foundry.toml declares no `fs_permissions`, and
// widening that just to read this one field isn't worth it — FFI is
// already the established pattern in this repo for reaching bls-validators/).
console.log(JSON.stringify({ pubkeys, aggregatePubkeyCompressed: keys.aggregatePubkeyCompressed ?? null }));
