#!/usr/bin/env -S npx tsx
// FFI helper for contracts/test/LightClientVerifierBLSReal.t.sol's final
// check — the aggregate pubkey of PARTICIPATING validators (not the whole
// committee's SSZ aggregate_pubkey, a different value — see comment below)
// and the real aggregate signature, both EIP-2537-encoded, from the frozen
// real_sync_committee_snapshot.json.
//
// Usage: npx tsx dump_real_verification_inputs.ts

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { bls12_381 } from "@noble/curves/bls12-381.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function fpHex(n: bigint): string {
  return n.toString(16).padStart(128, "0");
}
function g1Hex(point: { toAffine: () => { x: bigint; y: bigint } }): string {
  const p = point.toAffine();
  return "0x" + fpHex(p.x) + fpHex(p.y);
}
function g2Hex(point: { toAffine: () => { x: { c0: bigint; c1: bigint }; y: { c0: bigint; c1: bigint } } }): string {
  const p = point.toAffine();
  return "0x" + fpHex(p.x.c0) + fpHex(p.x.c1) + fpHex(p.y.c0) + fpHex(p.y.c1);
}
function decodeParticipationBitmap(hex: string): number[] {
  const bytes = Buffer.from(hex.slice(2), "hex");
  const indices: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    for (let bit = 0; bit < 8; bit++) if ((bytes[i]! >> bit) & 1) indices.push(i * 8 + bit);
  }
  return indices;
}

const snapshot = JSON.parse(fs.readFileSync(path.join(__dirname, "real_sync_committee_snapshot.json"), "utf8"));

// IMPORTANT: this is NOT the same as committee.aggregatePubkeyCompressed
// (the SSZ SyncCommittee.aggregate_pubkey field, which sums ALL 512
// members regardless of who signed this particular update, used only for
// the merkle-proof check). The pairing check needs the aggregate of ONLY
// the validators whose bit is set in sync_committee_bits for THIS update.
const bits = decodeParticipationBitmap(snapshot.syncAggregate.participationBitmapSsz);
const participatingPubkeys = bits.map((i: number) => bls12_381.G1.Point.fromHex(snapshot.committee.pubkeysCompressed[i].slice(2)));
const aggPubkey = bls12_381.longSignatures.aggregatePublicKeys(participatingPubkeys);

const signature = bls12_381.G2.Point.fromHex(snapshot.syncAggregate.signature.slice(2));

console.log(
  JSON.stringify({
    participatingAggPubkeyEip2537: g1Hex(aggPubkey),
    signatureEip2537: g2Hex(signature),
    participantCount: bits.length,
  })
);
