#!/usr/bin/env -S npx tsx
// Cross-check helper for contracts/test/RFC9380.t.sol — computes the
// hash_to_curve message point (RFC9380, BLS12-381 G2, Ethereum's real
// POP DST) off-chain via noble/curves, EIP-2537-encoded, for a given
// message. Used to prove Solidity's RFC9380.sol produces the EXACT SAME
// point on-chain.
//
// Usage: npx tsx dump_message_point.ts <messageHex32Bytes>
import { bls12_381 } from "@noble/curves/bls12-381.js";

const POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const [, , messageHex] = process.argv;
if (!messageHex) {
  console.error("usage: dump_message_point.ts <messageHex32Bytes>");
  process.exit(1);
}

function fpHex(n: bigint): string {
  return n.toString(16).padStart(128, "0");
}

const message = Buffer.from(messageHex.startsWith("0x") ? messageHex.slice(2) : messageHex, "hex");
const point = bls12_381.longSignatures.hash(new Uint8Array(message), POP_DST);
const affine = point.toAffine();

console.log("0x" + fpHex(affine.x.c0) + fpHex(affine.x.c1) + fpHex(affine.y.c0) + fpHex(affine.y.c1));
