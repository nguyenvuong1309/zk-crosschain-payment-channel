#!/usr/bin/env -S npx tsx
// Reads snarkjs's proof.json + public.json and prints the flat JSON shape
// Foundry's `vm.parseJsonUintArray` expects (see ChannelStateProof.t.sol).
// Usage: npx tsx format_ffi_output.ts <proof.json> <public.json>
import fs from "fs";

interface Groth16Proof {
  pi_a: [string, string, string];
  pi_b: [[string, string], [string, string], [string, string]];
  pi_c: [string, string, string];
}

const [, , proofPath, publicPath] = process.argv;
if (!proofPath || !publicPath) {
  throw new Error("usage: format_ffi_output.ts <proof.json> <public.json>");
}
const proof: Groth16Proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
const pubSignals: string[] = JSON.parse(fs.readFileSync(publicPath, "utf8"));

// Standard snarkjs G2 coordinate swap for Solidity verifiers (matches
// `snarkjs zkey export soliditycalldata`'s convention).
const a = [proof.pi_a[0], proof.pi_a[1]];
const b0 = [proof.pi_b[0][1], proof.pi_b[0][0]];
const b1 = [proof.pi_b[1][1], proof.pi_b[1][0]];
const c = [proof.pi_c[0], proof.pi_c[1]];

process.stdout.write(JSON.stringify({ a, b0, b1, c, pubSignals }));
