#!/usr/bin/env -S npx tsx
// Milestone 5 step 6 (see PLAN.md) — captures a single REAL Ethereum
// mainnet light-client snapshot (fork info, 512-key sync committee +
// merkle branch, one real attested header + aggregate signature) into a
// FROZEN JSON fixture, so contracts/test/LightClientVerifierBLSReal.t.sol
// can verify against genuine mainnet data WITHOUT depending on a live
// network connection at test/CI time (the data keeps changing block to
// block — freezing it is what makes the test reproducible).
//
// Re-run this to refresh the snapshot to a newer block; the frozen file is
// committed to git either way (it's real historical data, not a secret).
//
// The finalized root + genesis_validators_root this snapshot anchors to
// now come from `getTrustlessCheckpoint()` (trustless_bootstrap.ts,
// Milestone 5's last open item) — cross-checked against 3 independent
// beacon node operators instead of trusted from whichever single node this
// script happens to talk to. See that file's header comment for why.
//
// Usage: npx tsx capture_real_snapshot.ts [beaconApiUrl]

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { createHash } from "crypto";
import { bls12_381 } from "@noble/curves/bls12-381.js";
import { getTrustlessCheckpoint } from "./trustless_bootstrap.js";

function sha256(a: Uint8Array, b: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(a).update(b).digest());
}
function hexToBytes(hex: string): Uint8Array {
  return new Uint8Array(Buffer.from(hex.startsWith("0x") ? hex.slice(2) : hex, "hex"));
}
function bytesToHex(b: Uint8Array): string {
  return "0x" + Buffer.from(b).toString("hex");
}
function uint64Chunk(v: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  new DataView(buf.buffer).setBigUint64(0, v, true);
  return buf;
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

/// hash_tree_root(BeaconBlockHeader) — same algorithm as
/// sync_committee_probe.ts / dump_signing_root.ts, duplicated here (small,
/// self-contained scripts by this repo's convention) to independently
/// confirm the light-client node's bootstrap.header really IS the header
/// for the trustless-checked finalizedRoot, not a mismatched one.
function hashTreeRootHeader(h: { slot: string; proposer_index: string; parent_root: string; state_root: string; body_root: string }): Uint8Array {
  return merkleize([
    uint64Chunk(BigInt(h.slot)),
    uint64Chunk(BigInt(h.proposer_index)),
    hexToBytes(h.parent_root),
    hexToBytes(h.state_root),
    hexToBytes(h.body_root),
  ]);
}

const __dirname = path.dirname(fileURLToPath(import.meta.url));

async function fetchJson(baseUrl: string, p: string): Promise<any> {
  const res = await fetch(`${baseUrl}${p}`);
  if (!res.ok) throw new Error(`${p} -> HTTP ${res.status} ${await res.text()}`);
  return res.json();
}

function fpHex(n: bigint): string {
  return n.toString(16).padStart(128, "0");
}

/// Converts a real Ethereum 48-byte COMPRESSED G1 pubkey to the 128-byte
/// EIP-2537 (uncompressed x||y) encoding LightClientVerifierBLS*.sol's
/// G1ADD/pairing precompile calls need — same conversion
/// generate_keys_general.ts's g1Hex does for demo keys, applied here to
/// real committee pubkeys instead of self-derived ones.
function compressedToEip2537(compressedHex: string): string {
  const point = bls12_381.G1.Point.fromHex(compressedHex.startsWith("0x") ? compressedHex.slice(2) : compressedHex);
  const affine = point.toAffine();
  return "0x" + fpHex(affine.x) + fpHex(affine.y);
}

async function main() {
  const checkpoint = await getTrustlessCheckpoint();
  const beaconApi = checkpoint.lightClientNodeUrl;
  console.error(`[capture] trustless-checked finalized root: ${checkpoint.finalizedRoot}`);
  console.error(`[capture] fetching light-client payload from: ${beaconApi}`);

  const fork = (await fetchJson(beaconApi, "/eth/v1/beacon/states/head/fork")).data;
  const bootstrap = (await fetchJson(beaconApi, `/eth/v1/beacon/light_client/bootstrap/${checkpoint.finalizedRoot}`)).data;
  const update = (await fetchJson(beaconApi, "/eth/v1/beacon/light_client/finality_update")).data;

  // Defense in depth: the light-client node was asked for the bootstrap AT
  // the trustless-checked finalizedRoot, but nothing so far confirmed it
  // actually returned a header that hashes to that exact root rather than
  // some other one — recompute hash_tree_root(bootstrap.header.beacon)
  // independently and require it to match.
  const returnedHeaderRoot = bytesToHex(hashTreeRootHeader(bootstrap.header.beacon));
  if (returnedHeaderRoot.toLowerCase() !== checkpoint.finalizedRoot.toLowerCase()) {
    throw new Error(
      `light-client node returned a header for a DIFFERENT root than requested: expected ${checkpoint.finalizedRoot}, got ${returnedHeaderRoot}`
    );
  }
  console.error(`[capture] bootstrap.header hash_tree_root matches the trustless-checked finalized root — confirmed`);

  const committee = bootstrap.current_sync_committee;
  console.error(`[capture] committee size: ${committee.pubkeys.length}, converting to EIP-2537...`);
  const pubkeysEip2537 = committee.pubkeys.map(compressedToEip2537);
  const aggregatePubkeyEip2537 = compressedToEip2537(committee.aggregate_pubkey);

  const snapshot = {
    note: "REAL Ethereum mainnet light-client snapshot (Milestone 5 step 6) — frozen at capture time so contracts/test/LightClientVerifierBLSReal.t.sol has reproducible, non-flaky real data. Re-run capture_real_snapshot.ts to refresh. genesisValidatorsRoot/finalizedRoot below are trustless-checked (Milestone 5's last item — see trustless_bootstrap.ts), not trusted from one node.",
    capturedAt: new Date().toISOString(),
    beaconApi,
    genesisValidatorsRoot: checkpoint.genesisValidatorsRoot,
    trustlessCheckedFinalizedRoot: checkpoint.finalizedRoot,
    forkCurrentVersion: fork.current_version,
    forkEpoch: fork.epoch,
    bootstrapHeaderStateRoot: bootstrap.header.beacon.state_root,
    currentSyncCommitteeBranch: bootstrap.current_sync_committee_branch,
    committee: {
      pubkeysCompressed: committee.pubkeys,
      pubkeysEip2537,
      aggregatePubkeyCompressed: committee.aggregate_pubkey,
      aggregatePubkeyEip2537,
    },
    attestedHeader: update.attested_header.beacon,
    syncAggregate: {
      participationBitmapSsz: update.sync_aggregate.sync_committee_bits,
      signature: update.sync_aggregate.sync_committee_signature,
    },
  };

  const outPath = path.join(__dirname, "real_sync_committee_snapshot.json");
  fs.writeFileSync(outPath, JSON.stringify(snapshot, null, 2));
  console.error(`[capture] wrote ${outPath}`);
  console.error(`[capture] attested_header.slot = ${update.attested_header.beacon.slot}, fork = ${fork.current_version}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
