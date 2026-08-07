#!/usr/bin/env -S npx tsx
// Lightweight self-check (no test framework needed for 2 assertions):
//   1. keys.json is reproducible from generate_keys.ts (catches silent
//      drift between the committed file and the script that produces it).
//   2. sign.ts produces a signature that off-chain pairing math accepts —
//      the same equation LightClientVerifierBLS.sol checks on-chain via
//      precompile (see contracts/test/BLS12381Test for the on-chain half).
//
// Run: npx tsx test.ts

import assert from "assert";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { signAggregate, messagePoint } from "./sign.js";
import keysJson from "./keys.json" with { type: "json" };

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function test(name: string, fn: () => void): void {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (err) {
    console.error(`FAIL - ${name}`);
    console.error(err);
    process.exitCode = 1;
  }
}

test("keys.json matches generate_keys.ts output", () => {
  const before = fs.readFileSync(path.join(__dirname, "keys.json"), "utf8");
  execSync("npx tsx generate_keys.ts", { cwd: __dirname, stdio: "pipe" });
  const after = fs.readFileSync(path.join(__dirname, "keys.json"), "utf8");
  assert.strictEqual(after, before, "keys.json is out of date — run `npx tsx generate_keys.ts` and commit the result");
});

test("aggregate signature from a real quorum satisfies the pairing equation", () => {
  const keys = keysJson as { validators: { pubkey: string }[] };
  const participantBitmap = 0b00111n; // validators 0,1,2
  const { aggSig } = signAggregate({ chainId: 31337n, blockNumber: 1n, stateRoot: 12345n, participantBitmap });

  const M = messagePoint(31337n, 1n, 12345n);
  const aggPubkey = [0, 1, 2].reduce((acc: any, i) => {
    const pub = pubkeyFromEip2537(keys.validators[i]!.pubkey);
    return acc === null ? pub : acc.add(pub);
  }, null);

  const sigPoint = sigFromEip2537(aggSig);
  const lhs = bls12_381.pairing(aggPubkey, M);
  const rhs = bls12_381.pairing(bls12_381.G1.Point.BASE, sigPoint);
  assert.ok(bls12_381.fields.Fp12.eql(lhs, rhs), "e(aggPubkey, M) must equal e(G1, aggSig)");
});

test("a signature from the wrong quorum fails the pairing equation", () => {
  const { aggSig } = signAggregate({ chainId: 31337n, blockNumber: 1n, stateRoot: 12345n, participantBitmap: 0b00011n }); // only 0,1

  const keys = keysJson as { validators: { pubkey: string }[] };
  const M = messagePoint(31337n, 1n, 12345n);
  // Claim validators 0,1,2 (aggPubkey includes 2, who never signed).
  const aggPubkey = [0, 1, 2].reduce((acc: any, i) => {
    const pub = pubkeyFromEip2537(keys.validators[i]!.pubkey);
    return acc === null ? pub : acc.add(pub);
  }, null);

  const sigPoint = sigFromEip2537(aggSig);
  const lhs = bls12_381.pairing(aggPubkey, M);
  const rhs = bls12_381.pairing(bls12_381.G1.Point.BASE, sigPoint);
  assert.ok(!bls12_381.fields.Fp12.eql(lhs, rhs), "mismatched quorum must NOT satisfy the pairing equation");
});

/// Parses an EIP-2537-encoded G1 point (0x + 128-byte hex: x then y, each
/// 64-byte zero-padded) into a noble Point via fromAffine.
function pubkeyFromEip2537(hex: string) {
  const h = hex.slice(2);
  const x = BigInt("0x" + h.slice(0, 128));
  const y = BigInt("0x" + h.slice(128, 256));
  return bls12_381.G1.Point.fromAffine({ x, y });
}

/// Same, for a G2 point (0x + 256-byte hex: x.c0, x.c1, y.c0, y.c1).
function sigFromEip2537(hex: string) {
  const h = hex.slice(2);
  const xc0 = BigInt("0x" + h.slice(0, 128));
  const xc1 = BigInt("0x" + h.slice(128, 256));
  const yc0 = BigInt("0x" + h.slice(256, 384));
  const yc1 = BigInt("0x" + h.slice(384, 512));
  return bls12_381.G2.Point.fromAffine({ x: { c0: xc0, c1: xc1 }, y: { c0: yc0, c1: yc1 } });
}

if (process.exitCode) process.exit(process.exitCode);
