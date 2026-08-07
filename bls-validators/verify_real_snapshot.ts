#!/usr/bin/env -S npx tsx
// Milestone 5 step 6 — re-verifies real_sync_committee_snapshot.json
// entirely offline (no network), proving the frozen copy is self-consistent
// (not corrupted/mistranscribed by capture_real_snapshot.ts) before
// contracts/test/LightClientVerifierBLSReal.t.sol trusts it as a fixture.
// Same verification logic as sync_committee_probe.ts (Milestone 5 steps 1-2)
// but sourced from the frozen file instead of a live beacon API call.
//
// Usage: npx tsx verify_real_snapshot.ts

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { createHash } from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
const DOMAIN_SYNC_COMMITTEE = "0x07000000";
const CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA = 86;

function sha256(a: Uint8Array, b: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(a).update(b).digest());
}
function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex.startsWith("0x") ? hex.slice(2) : hex, "hex"));
}
function bytesToHex(b: Uint8Array): string {
  return "0x" + Buffer.from(b).toString("hex");
}
function merkleize(chunks: Uint8Array[]): Uint8Array {
  let layer = chunks;
  let size = 1;
  while (size < layer.length) size *= 2;
  const zero32 = new Uint8Array(32);
  while (layer.length < size) layer = [...layer, zero32];
  while (layer.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < layer.length; i += 2) next.push(sha256(layer[i]!, layer[i + 1]!));
    layer = next;
  }
  return layer[0] ?? new Uint8Array(32);
}
function uint64Chunk(v: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  new DataView(buf.buffer).setBigUint64(0, v, true);
  return buf;
}
function bytes32Chunk(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== 32) throw new Error(`expected 32 bytes: ${hex}`);
  return b;
}
function hashTreeRootBytes48(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== 48) throw new Error(`expected 48 bytes: ${hex}`);
  const chunk1 = new Uint8Array(32);
  chunk1.set(b.slice(32, 48), 0);
  return merkleize([b.slice(0, 32), chunk1]);
}
function isValidMerkleBranch(leaf: Uint8Array, branch: Uint8Array[], depth: number, index: number, root: Uint8Array): boolean {
  let value = leaf;
  for (let i = 0; i < depth; i++) {
    value = (index >> i) & 1 ? sha256(branch[i]!, value) : sha256(value, branch[i]!);
  }
  return bytesToHex(value) === bytesToHex(root);
}
function decodeParticipationBitmap(hex: string): number[] {
  const bytes = hexToBytes(hex);
  const indices: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    for (let bit = 0; bit < 8; bit++) if ((bytes[i]! >> bit) & 1) indices.push(i * 8 + bit);
  }
  return indices;
}

interface BeaconBlockHeader {
  slot: string;
  proposer_index: string;
  parent_root: string;
  state_root: string;
  body_root: string;
}
function hashTreeRootHeader(h: BeaconBlockHeader): Uint8Array {
  return merkleize([
    uint64Chunk(BigInt(h.slot)),
    uint64Chunk(BigInt(h.proposer_index)),
    bytes32Chunk(h.parent_root),
    bytes32Chunk(h.state_root),
    bytes32Chunk(h.body_root),
  ]);
}
function computeDomain(currentVersionHex: string, genesisValidatorsRootHex: string): Uint8Array {
  const versionChunk = new Uint8Array(32);
  versionChunk.set(hexToBytes(currentVersionHex).slice(0, 4), 0);
  const forkDataRoot = merkleize([versionChunk, bytes32Chunk(genesisValidatorsRootHex)]);
  const domain = new Uint8Array(32);
  domain.set(hexToBytes(DOMAIN_SYNC_COMMITTEE).slice(0, 4), 0);
  domain.set(forkDataRoot.slice(0, 28), 4);
  return domain;
}

const snapshot = JSON.parse(fs.readFileSync(path.join(__dirname, "real_sync_committee_snapshot.json"), "utf8"));

let failed = false;
function check(name: string, ok: boolean) {
  console.log(`${ok ? "ok" : "FAIL"} - ${name}`);
  if (!ok) failed = true;
}

// 1. Committee is really in the beacon state (SSZ merkle proof).
const pubkeysCompressed: string[] = snapshot.committee.pubkeysCompressed;
const committeeRoot = merkleize([
  merkleize(pubkeysCompressed.map(hashTreeRootBytes48)),
  hashTreeRootBytes48(snapshot.committee.aggregatePubkeyCompressed),
]);
const branch = snapshot.currentSyncCommitteeBranch.map(hexToBytes);
const stateRoot = bytes32Chunk(snapshot.bootstrapHeaderStateRoot);
check(
  "committee merkle branch verifies against bootstrap header state_root",
  isValidMerkleBranch(committeeRoot, branch, branch.length, CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA, stateRoot)
);

// 2. The aggregate BLS signature over the attested header verifies.
const domain = computeDomain(snapshot.forkCurrentVersion, snapshot.genesisValidatorsRoot);
const objectRoot = hashTreeRootHeader(snapshot.attestedHeader);
const signingRoot = merkleize([objectRoot, domain]);

const bits = decodeParticipationBitmap(snapshot.syncAggregate.participationBitmapSsz);
const participatingPubkeys = bits.map((i) => hexToBytes(pubkeysCompressed[i]!));
const aggPubkey = bls12_381.longSignatures.aggregatePublicKeys(participatingPubkeys);
const message = bls12_381.longSignatures.hash(signingRoot, POP_DST);
const sigOk = bls12_381.longSignatures.verify(hexToBytes(snapshot.syncAggregate.signature), message, aggPubkey);
check(`BLS aggregate signature verifies (${bits.length}/${pubkeysCompressed.length} participated)`, sigOk);

// 3. pubkeysEip2537 (what actually gets registered on-chain) round-trips to
// the same compressed pubkeys — catches a botched EIP-2537 conversion.
const pubkeysEip2537: string[] = snapshot.committee.pubkeysEip2537;
let eip2537Ok = pubkeysEip2537.length === pubkeysCompressed.length;
if (eip2537Ok) {
  for (let i = 0; i < 5; i++) {
    // spot-check first 5, not all 512 — this is a sanity check, not the
    // main proof
    const affine = bls12_381.G1.Point.fromHex(pubkeysCompressed[i]!.slice(2)).toAffine();
    const expected = "0x" + affine.x.toString(16).padStart(128, "0") + affine.y.toString(16).padStart(128, "0");
    if (expected !== pubkeysEip2537[i]) eip2537Ok = false;
  }
}
check("pubkeysEip2537 spot-check matches recompressed pubkeysCompressed", eip2537Ok);

console.log(`\nSnapshot captured ${snapshot.capturedAt}, attested slot ${snapshot.attestedHeader.slot}, fork ${snapshot.forkCurrentVersion}`);
if (failed) process.exit(1);
