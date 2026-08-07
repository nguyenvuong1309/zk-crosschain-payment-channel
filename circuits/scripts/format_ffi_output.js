#!/usr/bin/env node
// Reads snarkjs's proof.json + public.json and prints the flat JSON shape
// Foundry's `vm.parseJsonUintArray` expects (see ChannelStateProof.t.sol).
// Usage: node format_ffi_output.js <proof.json> <public.json>
const fs = require("fs");

const [, , proofPath, publicPath] = process.argv;
const proof = JSON.parse(fs.readFileSync(proofPath, "utf8"));
const pubSignals = JSON.parse(fs.readFileSync(publicPath, "utf8"));

// Standard snarkjs G2 coordinate swap for Solidity verifiers (matches
// `snarkjs zkey export soliditycalldata`'s convention).
const a = [proof.pi_a[0], proof.pi_a[1]];
const b0 = [proof.pi_b[0][1], proof.pi_b[0][0]];
const b1 = [proof.pi_b[1][1], proof.pi_b[1][0]];
const c = [proof.pi_c[0], proof.pi_c[1]];

process.stdout.write(JSON.stringify({ a, b0, b1, c, pubSignals }));
