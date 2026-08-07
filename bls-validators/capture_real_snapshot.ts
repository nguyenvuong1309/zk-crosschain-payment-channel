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
// Usage: npx tsx capture_real_snapshot.ts [beaconApiUrl]

import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { bls12_381 } from "@noble/curves/bls12-381.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BEACON_API = process.argv[2] ?? "https://ethereum-beacon-api.publicnode.com";

async function fetchJson(p: string): Promise<any> {
  const res = await fetch(`${BEACON_API}${p}`);
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
  console.error(`[capture] beacon API: ${BEACON_API}`);

  const genesis = (await fetchJson("/eth/v1/beacon/genesis")).data;
  const fork = (await fetchJson("/eth/v1/beacon/states/head/fork")).data;
  const finalizedRoot: string = (await fetchJson("/eth/v1/beacon/blocks/finalized/root")).data.root;
  const bootstrap = (await fetchJson(`/eth/v1/beacon/light_client/bootstrap/${finalizedRoot}`)).data;
  const update = (await fetchJson("/eth/v1/beacon/light_client/finality_update")).data;

  const committee = bootstrap.current_sync_committee;
  console.error(`[capture] committee size: ${committee.pubkeys.length}, converting to EIP-2537...`);
  const pubkeysEip2537 = committee.pubkeys.map(compressedToEip2537);
  const aggregatePubkeyEip2537 = compressedToEip2537(committee.aggregate_pubkey);

  const snapshot = {
    note: "REAL Ethereum mainnet light-client snapshot (Milestone 5 step 6) — frozen at capture time so contracts/test/LightClientVerifierBLSReal.t.sol has reproducible, non-flaky real data. Re-run capture_real_snapshot.ts to refresh.",
    capturedAt: new Date().toISOString(),
    beaconApi: BEACON_API,
    genesisValidatorsRoot: genesis.genesis_validators_root,
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
