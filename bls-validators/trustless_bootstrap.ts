#!/usr/bin/env -S npx tsx
// Milestone 5's last open item (see PLAN.md) — "trustless bootstrap":
// every earlier Milestone 5 script (sync_committee_probe.ts,
// capture_real_snapshot.ts) trusted ONE public beacon node's HTTP
// responses for the two values everything else gets anchored to —
// `genesis_validators_root` and the finalized block root. Every downstream
// check (BLS signature, SSZ merkle proof) is self-verifying crypto — but if
// that one node simply LIED about which block is finalized, all of that
// crypto would still "verify" self-consistently against a fabricated
// checkpoint, and nothing built so far would catch it.
//
// This script closes that gap the only way that's actually checkable
// without running your own node: query the SAME two values from several
// INDEPENDENT beacon node operators and require them to agree. Light
// client-specific endpoints (bootstrap/finality_update) turned out to only
// be enabled on one of the free public nodes tried (see comment below) —
// but they don't need independent corroboration themselves: once the
// finalized root is trusted (via this cross-check), the committee/proof/
// signature built ON TOP of it is already cryptographically self-verifying
// (Milestone 5 steps 1-2). Cross-checking the root is the missing piece,
// not re-deriving everything N times.
//
// Usage: npx tsx trustless_bootstrap.ts

import { fileURLToPath } from "url";

interface NodeConfig {
  name: string;
  url: string;
}

// All 3 confirmed independently reachable and serving real mainnet data as
// of this writing (see PLAN.md Milestone 5 for how these were found —
// most candidate public endpoints tried did NOT work). Independent
// operators: PublicNode, Attestant, beaconcha.in — not the same
// infrastructure, so agreement between them is meaningful, not
// coincidental.
const NODES: NodeConfig[] = [
  { name: "publicnode", url: "https://ethereum-beacon-api.publicnode.com" },
  { name: "attestant-checkpoint-sync", url: "https://mainnet-checkpoint-sync.attestant.io" },
  { name: "beaconcha.in-checkpoint-sync", url: "https://sync-mainnet.beaconcha.in" },
];

// The only node found (of these 3) that also serves the Light Client API
// module (bootstrap/finality_update) — not all beacon node operators
// enable it, it's an optional Beacon API extra. Once the root below is
// cross-checked, it's safe to fetch the (self-verifying) light-client
// payload from just this one, same as before.
const LIGHT_CLIENT_NODE = NODES[0]!;

async function fetchJson(baseUrl: string, path: string): Promise<any> {
  const res = await fetch(`${baseUrl}${path}`, { signal: AbortSignal.timeout(10_000) });
  if (!res.ok) throw new Error(`${baseUrl}${path} -> HTTP ${res.status}`);
  return res.json();
}

function normalizeRoot(root: string): string {
  // Some node operators omit the "0x" prefix on this specific endpoint
  // (observed on the checkpoint-sync nodes above) — cosmetic, not a
  // disagreement, normalize before comparing.
  return (root.startsWith("0x") ? root : "0x" + root).toLowerCase();
}

export interface TrustlessCheckpoint {
  genesisValidatorsRoot: string;
  finalizedRoot: string;
  lightClientNodeUrl: string;
}

/// Cross-checks genesis_validators_root + finalized block root across
/// NODES, returning the agreed values (throws if fewer than 2/3 agree) —
/// the reusable half of this script, called by capture_real_snapshot.ts
/// instead of that script trusting one node's /blocks/finalized/root
/// directly. See this file's header comment for why this specific check
/// closes Milestone 5's last open trust gap.
export async function getTrustlessCheckpoint(): Promise<TrustlessCheckpoint> {
  const results = await Promise.all(
    NODES.map(async (node) => {
      const [genesis, finalized] = await Promise.all([
        fetchJson(node.url, "/eth/v1/beacon/genesis"),
        fetchJson(node.url, "/eth/v1/beacon/blocks/finalized/root"),
      ]);
      return {
        node: node.name,
        genesisValidatorsRoot: normalizeRoot(genesis.data.genesis_validators_root),
        finalizedRoot: normalizeRoot(finalized.data.root),
      };
    })
  );

  const genesisRoots = new Set(results.map((r) => r.genesisValidatorsRoot));
  if (genesisRoots.size !== 1) {
    throw new Error("trustless bootstrap: nodes disagree on genesis_validators_root (different networks?)");
  }

  const rootCounts = new Map<string, number>();
  for (const r of results) rootCounts.set(r.finalizedRoot, (rootCounts.get(r.finalizedRoot) ?? 0) + 1);
  const [agreedRoot, agreedCount] = [...rootCounts.entries()].sort((a, b) => b[1] - a[1])[0]!;

  if (agreedCount < 2) {
    throw new Error("trustless bootstrap: no finalized root agreed on by at least 2 of 3 independent nodes");
  }

  return { genesisValidatorsRoot: [...genesisRoots][0]!, finalizedRoot: agreedRoot, lightClientNodeUrl: LIGHT_CLIENT_NODE.url };
}

async function main() {
  console.error(`[bootstrap] querying ${NODES.length} independent nodes for genesis_validators_root + finalized root...`);
  const checkpoint = await getTrustlessCheckpoint();
  console.error(`[bootstrap] OK — independent nodes agree: finalized root = ${checkpoint.finalizedRoot}`);
  console.error(`[bootstrap] safe to fetch the light-client payload for this root from ${checkpoint.lightClientNodeUrl} now`);
  console.error("[bootstrap] (everything from here is cryptographically self-verifying against the agreed root — see sync_committee_probe.ts)");
  console.log(JSON.stringify(checkpoint));
}

// Only run as a CLI when invoked directly (`npx tsx trustless_bootstrap.ts`)
// — not when imported by capture_real_snapshot.ts for getTrustlessCheckpoint().
const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
