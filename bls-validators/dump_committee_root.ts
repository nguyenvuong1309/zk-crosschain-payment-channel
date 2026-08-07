#!/usr/bin/env -S npx tsx
// Milestone 5 step 5 helper — computes hash_tree_root(SyncCommittee) for a
// keys_general_*.json demo committee, using the SAME algorithm already
// verified against REAL Ethereum mainnet data in sync_committee_probe.ts
// (Milestone 5 step 2). Used by
// contracts/test/SSZ.t.sol to cross-check SSZ.sol's on-chain computation
// against this off-chain one for the demo committee (which, unlike real
// mainnet data, has no live beacon-state root to check against — this is
// what CAN be verified for a synthetic committee: on-chain and off-chain
// agree on the same root).
//
// Usage: npx tsx dump_committee_root.ts <keysJsonPath>

import fs from "fs";
import { createHash } from "crypto";

const [, , keysJsonPath] = process.argv;
if (!keysJsonPath) {
  console.error("usage: dump_committee_root.ts <keysJsonPath>");
  process.exit(1);
}

function sha256(a: Uint8Array, b: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(a).update(b).digest());
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  return new Uint8Array(Buffer.from(clean, "hex"));
}

function bytesToHex(bytes: Uint8Array): string {
  return "0x" + Buffer.from(bytes).toString("hex");
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

function hashTreeRootBytes48(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== 48) throw new Error(`expected 48-byte hex, got ${b.length} bytes: ${hex}`);
  const chunk0 = b.slice(0, 32);
  const chunk1 = new Uint8Array(32);
  chunk1.set(b.slice(32, 48), 0);
  return merkleize([chunk0, chunk1]);
}

function hashTreeRootSyncCommittee(pubkeys: string[], aggregatePubkey: string): Uint8Array {
  const pubkeysRoot = merkleize(pubkeys.map(hashTreeRootBytes48));
  return merkleize([pubkeysRoot, hashTreeRootBytes48(aggregatePubkey)]);
}

const keys = JSON.parse(fs.readFileSync(keysJsonPath, "utf8")) as {
  validators: { pubkeyCompressed: string }[];
  aggregatePubkeyCompressed: string;
};

const root = hashTreeRootSyncCommittee(
  keys.validators.map((v) => v.pubkeyCompressed),
  keys.aggregatePubkeyCompressed
);

console.log(bytesToHex(root));
