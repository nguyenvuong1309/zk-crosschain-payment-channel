#!/usr/bin/env -S npx tsx
// Generates the demo BLS12-381 validator committee — 5 deterministic
// (fixed-seed, demo-only) keypairs — and writes keys.json. Re-run this if
// you ever need to regenerate (e.g. after confirming a transcription bug,
// see git history) rather than hand-editing keys.json.

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { bls12_381 } from "@noble/curves/bls12-381.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const NUM_VALIDATORS = 5;

function fpHex(n: bigint): string {
  return n.toString(16).padStart(128, "0"); // 64 bytes = 128 hex chars, EIP-2537 padded Fp encoding
}

function g1Hex(point: { toAffine?: () => { x: bigint; y: bigint } } & { x?: bigint; y?: bigint }): string {
  const p = point.toAffine ? point.toAffine() : (point as { x: bigint; y: bigint });
  return "0x" + fpHex(p.x) + fpHex(p.y);
}

// SHA256 produces a full 256-bit value, but the BLS12-381 scalar field
// (Fr) order is a ~255-bit prime — a raw hash can (and, for 2 of our 5 demo
// seeds, DID during testing) exceed it, which noble's Point.multiply
// correctly rejects as "invalid scalar: out of range". Reduce into
// [1, ORDER-1] instead of using the raw hash directly.
function deriveSecretKey(seed: string): bigint {
  const hash = crypto.createHash("sha256").update(seed).digest();
  const reduced = (BigInt("0x" + hash.toString("hex")) % (bls12_381.fields.Fr.ORDER - 1n)) + 1n;
  return reduced;
}

interface ValidatorKey {
  seed: string;
  secretKey: string;
  pubkey: string;
}

const validators: ValidatorKey[] = Array.from({ length: NUM_VALIDATORS }, (_, i) => {
  const seed = `bls-validator-${i}`;
  const scalar = deriveSecretKey(seed);
  const sk = Buffer.from(scalar.toString(16).padStart(64, "0"), "hex");
  const pub = bls12_381.longSignatures.getPublicKey(sk);
  return { seed, secretKey: "0x" + sk.toString("hex"), pubkey: g1Hex(pub) };
});

const negG1Generator = g1Hex(bls12_381.G1.Point.BASE.negate());

const out = {
  note: "Demo-only BLS12-381 validator keys (Milestone 4) — deterministically derived from fixed seeds, NEVER use for real value. See README.md.",
  validators,
  negG1Generator,
};

fs.writeFileSync(path.join(__dirname, "keys.json"), JSON.stringify(out, null, 2));

// Sanity-check lengths before declaring success — exactly the bug class
// that motivated writing this script instead of hand-transcribing output.
for (const v of validators) {
  if ((v.secretKey.length - 2) / 2 !== 32) throw new Error(`${v.seed}: secretKey wrong length`);
  if ((v.pubkey.length - 2) / 2 !== 128) throw new Error(`${v.seed}: pubkey wrong length`);
}
if ((negG1Generator.length - 2) / 2 !== 128) throw new Error("negG1Generator wrong length");

console.error(`Wrote keys.json (${NUM_VALIDATORS} validators, all lengths verified).`);
