#!/usr/bin/env -S npx tsx
// FFI helper for contracts/test/RFC9380.t.sol — computes the REAL
// signing_root (domain-separated SSZ hash of the attested header) from the
// frozen real_sync_committee_snapshot.json, using the same algorithm
// already verified in verify_real_snapshot.ts. Prints it as a bare hex
// string.
//
// Usage: npx tsx dump_signing_root.ts
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createHash } from "crypto";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const DOMAIN_SYNC_COMMITTEE = "0x07000000";

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

const snapshot = JSON.parse(fs.readFileSync(path.join(__dirname, "real_sync_committee_snapshot.json"), "utf8"));
const h = snapshot.attestedHeader;

const objectRoot = merkleize([
  uint64Chunk(BigInt(h.slot)),
  uint64Chunk(BigInt(h.proposer_index)),
  bytes32Chunk(h.parent_root),
  bytes32Chunk(h.state_root),
  bytes32Chunk(h.body_root),
]);

const versionChunk = new Uint8Array(32);
versionChunk.set(hexToBytes(snapshot.forkCurrentVersion).slice(0, 4), 0);
const forkDataRoot = merkleize([versionChunk, bytes32Chunk(snapshot.genesisValidatorsRoot)]);
const domain = new Uint8Array(32);
domain.set(hexToBytes(DOMAIN_SYNC_COMMITTEE).slice(0, 4), 0);
domain.set(forkDataRoot.slice(0, 28), 4);

const signingRoot = merkleize([objectRoot, domain]);
console.log(bytesToHex(signingRoot));
