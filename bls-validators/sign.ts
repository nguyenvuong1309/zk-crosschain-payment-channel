// Off-chain BLS12-381 signing for the demo validator committee.
// Computes the SAME message-to-G2-point mapping LightClientVerifierBLS.sol
// computes on-chain (see that contract's `_hashToG2` doc comment), signs
// with each participating validator's real private key, and aggregates
// (G2 point addition) into a single signature ready for `updateState()`.
//
// Usage: npx tsx sign.ts <chainId> <blockNumber> <stateRoot> <participantBitmap>
//   e.g. npx tsx sign.ts 31337 1 12345 7   # bitmap 0b111 = validators 0,1,2

import { fileURLToPath } from "url";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { ethers } from "ethers";
import keysJson from "./keys.json" with { type: "json" };

const keys = keysJson as { validators: { secretKey: string }[] };

const NUM_VALIDATORS = 5;

function fpHex(n: bigint): string {
  return n.toString(16).padStart(128, "0");
}

function g2Hex(point: { toAffine?: () => any } & Record<string, any>): string {
  const p = point.toAffine ? point.toAffine() : point;
  return "0x" + fpHex(p.x.c0) + fpHex(p.x.c1) + fpHex(p.y.c0) + fpHex(p.y.c1);
}

/// Mirrors LightClientVerifierBLS.sol::_hashToG2 exactly.
export function messagePoint(chainId: bigint, blockNumber: bigint, stateRoot: bigint) {
  const u0 = BigInt(
    ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["string", "uint256", "uint256", "uint256"], ["BLS_MSG_U0", chainId, blockNumber, stateRoot]))
  );
  const u1 = BigInt(
    ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["string", "uint256", "uint256", "uint256"], ["BLS_MSG_U1", chainId, blockNumber, stateRoot]))
  );
  // @noble/curves' published .d.ts types mapToCurve's return as a plain
  // AffinePoint (no .multiply/.add), but at runtime it's actually already a
  // full G2 Point (this matched the working JS version exactly) — cast
  // through unknown rather than re-deriving it via fromAffine, which
  // rejects an already-projective point ("projective point not allowed").
  return bls12_381.G2.mapToCurve([u0, u1]) as unknown as InstanceType<typeof bls12_381.G2.Point>;
}

export interface SignAggregateResult {
  aggSig: string;
  participantBitmap: string;
}

/// @param opts.chainId/blockNumber/stateRoot  bigint values
/// @param opts.participantBitmap              bigint — bit i set => validator i signs
/// @returns { aggSig: "0x..." (256 bytes), participantBitmap }
export function signAggregate({
  chainId,
  blockNumber,
  stateRoot,
  participantBitmap,
}: {
  chainId: bigint;
  blockNumber: bigint;
  stateRoot: bigint;
  participantBitmap: bigint;
}): SignAggregateResult {
  const M = messagePoint(chainId, blockNumber, stateRoot);

  let aggSig: ReturnType<typeof M.multiply> | null = null;
  for (let i = 0; i < NUM_VALIDATORS; i++) {
    if (!((participantBitmap >> BigInt(i)) & 1n)) continue;
    const scalar = BigInt(keys.validators[i]!.secretKey);
    const sig = M.multiply(scalar);
    aggSig = aggSig === null ? sig : aggSig.add(sig);
  }
  if (aggSig === null) throw new Error("participantBitmap selects zero validators");

  return { aggSig: g2Hex(aggSig), participantBitmap: participantBitmap.toString() };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  const [, , chainId, blockNumber, stateRoot, participantBitmap] = process.argv;
  if (!chainId || !blockNumber || !stateRoot || !participantBitmap) {
    console.error("usage: npx tsx sign.ts <chainId> <blockNumber> <stateRoot> <participantBitmap>");
    process.exit(1);
  }
  const result = signAggregate({
    chainId: BigInt(chainId),
    blockNumber: BigInt(blockNumber),
    stateRoot: BigInt(stateRoot),
    participantBitmap: BigInt(participantBitmap),
  });
  console.log(JSON.stringify(result));
}
