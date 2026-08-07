#!/usr/bin/env -S npx tsx
// Milestone 5 — RFC9380-correct counterpart to sign_general.ts. That
// script's messagePoint() deliberately uses a simplified, non-standard
// curve mapping (see its header comment); this one uses noble/curves'
// REAL RFC9380 hash_to_curve (`longSignatures.hash`, Ethereum's actual
// `..._SSWU_RO_POP_` DST) — the same primitive
// contracts/src/RFC9380.sol implements on-chain, proven bit-identical in
// contracts/test/RFC9380.t.sol. Signatures from THIS script only verify
// against `LightClientVerifierBLSGeneralRFC9380.sol`, never against
// `LightClientVerifierBLSGeneral.sol` (different message-to-curve
// schemes — not interchangeable, see that contract's doc comment).
//
// Message = abi.encodePacked(uint256 chainId, uint256 blockNumber, uint256
// stateRoot) — same 96-byte layout Solidity's `abi.encodePacked` produces,
// so this must byte-for-byte match `updateState`'s own encoding.
//
// Usage: npx tsx sign_general_rfc9380.ts <keysJsonPath> <chainId> <blockNumber> <stateRoot> <participantCount>

import fs from "fs";
import { bls12_381 } from "@noble/curves/bls12-381.js";

const POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const [, , keysJsonPath, chainIdArg, blockNumberArg, stateRootArg, participantCountArg] = process.argv;
if (!keysJsonPath || !chainIdArg || !blockNumberArg || !stateRootArg || !participantCountArg) {
  console.error("usage: sign_general_rfc9380.ts <keysJsonPath> <chainId> <blockNumber> <stateRoot> <participantCount>");
  process.exit(1);
}

const keys = JSON.parse(fs.readFileSync(keysJsonPath, "utf8")) as {
  numValidators: number;
  validators: { secretKey: string }[];
};
const participantCount = Number(participantCountArg);
if (participantCount < 0 || participantCount > keys.numValidators) {
  throw new Error(`participantCount ${participantCount} out of range [0, ${keys.numValidators}]`);
}

function fpHex(n: bigint): string {
  return n.toString(16).padStart(128, "0");
}
function g2Hex(point: { toAffine: () => any }): string {
  const p = point.toAffine();
  return "0x" + fpHex(p.x.c0) + fpHex(p.x.c1) + fpHex(p.y.c0) + fpHex(p.y.c1);
}
function u256Bytes(value: bigint): Buffer {
  const buf = Buffer.alloc(32);
  buf.write(value.toString(16).padStart(64, "0"), "hex");
  return buf;
}
function encodeBitmap(numValidators: number, participating: (i: number) => boolean): string {
  const numBytes = Math.ceil(numValidators / 8);
  const bytes = new Uint8Array(numBytes);
  for (let i = 0; i < numValidators; i++) {
    if (participating(i)) bytes[i >> 3]! |= 1 << (i & 7);
  }
  return "0x" + Buffer.from(bytes).toString("hex");
}

const chainId = BigInt(chainIdArg);
const blockNumber = BigInt(blockNumberArg);
const stateRoot = BigInt(stateRootArg);

// abi.encodePacked(uint256,uint256,uint256) — 3 concatenated 32-byte
// big-endian words, exactly what updateState()'s Solidity call produces.
const message = Buffer.concat([u256Bytes(chainId), u256Bytes(blockNumber), u256Bytes(stateRoot)]);
const messagePoint = bls12_381.longSignatures.hash(new Uint8Array(message), POP_DST);

let aggSig: ReturnType<typeof messagePoint.multiply> | null = null;
for (let i = 0; i < participantCount; i++) {
  const scalar = BigInt(keys.validators[i]!.secretKey);
  const sig = messagePoint.multiply(scalar);
  aggSig = aggSig === null ? sig : aggSig.add(sig);
}

const participantBitmap = encodeBitmap(keys.numValidators, (i) => i < participantCount);

if (aggSig === null) {
  console.log(JSON.stringify({ aggSig: null, participantBitmap }));
} else {
  console.log(JSON.stringify({ aggSig: g2Hex(aggSig), participantBitmap }));
}
