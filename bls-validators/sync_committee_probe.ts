#!/usr/bin/env -S npx tsx
// Milestone 5 step 1 (see PLAN.md) — fetches REAL Ethereum mainnet sync
// committee data via the standard Beacon API light-client endpoints, and
// verifies the aggregate BLS signature against it OFF-CHAIN, entirely
// independent of any contract in this repo.
//
// This is exploratory/research code for Milestone 5, NOT part of the
// Milestone 3/4 demo pipeline — `consensus_proof.circom` and
// `LightClientVerifier(BLS).sol` still use the 5-key demo committee;
// nothing here changes that. What this proves: the full Altair
// light-client protocol data (512 real committee pubkeys + merkle branch +
// a real aggregate signature) fetched from a public beacon node forms a
// genuinely, independently verifiable BLS12-381 signature — the exact
// primitive Milestone 5 needs to eventually replace the demo committee
// with.
//
// Also verifies current_sync_committee_branch against the beacon state root
// (SSZ merkle proof — Milestone 5 step 2): proves the 512 pubkeys really
// are the committee the beacon state itself commits to, not just numbers
// the queried node handed us. This still trusts that
// bootstrap.data.header.beacon IS the real header at the requested root
// (single public node, no independent corroboration) — a genuine "trustless
// bootstrap" needs a checkpoint trusted some OTHER way (weak subjectivity,
// multiple independent nodes, etc.), out of scope here.
//
// Deliberately does NOT (yet, see PLAN.md Milestone 5's remaining items):
//   - touch any Solidity contract (LightClientVerifierBLSGeneral.sol, done
//     in Milestone 5 step 3, still uses its own simplified demo committee)
//
// Usage: npx tsx sync_committee_probe.ts [beaconApiUrl]
//   Defaults to a public PublicNode mainnet Beacon API mirror (no API key
//   needed, but it's a third party — swap in your own node/provider if you
//   don't want to trust it).

import { bls12_381 } from "@noble/curves/bls12-381.js";
import { createHash } from "crypto";

const BEACON_API = process.argv[2] ?? "https://ethereum-beacon-api.publicnode.com";

// Ethereum consensus uses the IETF "proof-of-possession" BLS ciphersuite
// for ALL signing (sync committee included) — NOT noble's default "_NUL_"
// (basic scheme) DST used elsewhere in this repo's own demo committee
// (see bls-validators/sign.ts, which intentionally does NOT match this).
// https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#bls-signatures
const POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

// https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/beacon-chain.md#domain-types
const DOMAIN_SYNC_COMMITTEE = "0x07000000";

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

// --- Minimal SSZ hash_tree_root, just enough for the fixed-size containers
// this script needs (BeaconBlockHeader, ForkData, SigningData) — every
// field in all three is a 32-byte chunk, so hash_tree_root is a plain
// balanced binary merkle tree of sha256 pairs, no variable-length/list SSZ
// machinery required.
// https://github.com/ethereum/consensus-specs/blob/master/ssz/simple-serialize.md#merkleization

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

function uint64Chunk(value: bigint): Uint8Array {
  const buf = new Uint8Array(32);
  new DataView(buf.buffer).setBigUint64(0, value, true); // SSZ uints are little-endian
  return buf;
}

function bytes32Chunk(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== 32) throw new Error(`expected 32-byte hex, got ${b.length} bytes: ${hex}`);
  return b;
}

interface BeaconBlockHeader {
  slot: string;
  proposer_index: string;
  parent_root: string;
  state_root: string;
  body_root: string;
}

function hashTreeRootBeaconBlockHeader(h: BeaconBlockHeader): Uint8Array {
  return merkleize([
    uint64Chunk(BigInt(h.slot)),
    uint64Chunk(BigInt(h.proposer_index)),
    bytes32Chunk(h.parent_root),
    bytes32Chunk(h.state_root),
    bytes32Chunk(h.body_root),
  ]);
}

// ForkData { current_version: Bytes4, genesis_validators_root: Bytes32 }
function computeForkDataRoot(currentVersionHex: string, genesisValidatorsRootHex: string): Uint8Array {
  const versionChunk = new Uint8Array(32);
  versionChunk.set(hexToBytes(currentVersionHex).slice(0, 4), 0); // right-padded to 32 bytes
  return merkleize([versionChunk, bytes32Chunk(genesisValidatorsRootHex)]);
}

function computeDomain(domainTypeHex: string, currentVersionHex: string, genesisValidatorsRootHex: string): Uint8Array {
  const forkDataRoot = computeForkDataRoot(currentVersionHex, genesisValidatorsRootHex);
  const domain = new Uint8Array(32);
  domain.set(hexToBytes(domainTypeHex).slice(0, 4), 0);
  domain.set(forkDataRoot.slice(0, 28), 4);
  return domain;
}

// SigningData { object_root: Bytes32, domain: Bytes32 }
function computeSigningRoot(objectRoot: Uint8Array, domain: Uint8Array): Uint8Array {
  return merkleize([objectRoot, domain]);
}

// --- SSZ hash_tree_root for SyncCommittee { pubkeys: Vector[BLSPubkey, 512],
// aggregate_pubkey: BLSPubkey }, and the generalized-index merkle branch
// check that proves a SyncCommittee root is really committed inside a
// BeaconState. https://github.com/ethereum/consensus-specs/blob/master/ssz/simple-serialize.md

// BLSPubkey = Bytes48 = Vector[uint8, 48], a COMPOSITE (not "basic") SSZ
// type — even on its own, hash_tree_root packs its 48 raw bytes into 32-byte
// chunks (2 chunks: 32 + 16-zero-padded-to-32) and merkleizes those.
function hashTreeRootBytes48(hex: string): Uint8Array {
  const b = hexToBytes(hex);
  if (b.length !== 48) throw new Error(`expected 48-byte hex, got ${b.length} bytes: ${hex}`);
  const chunk0 = b.slice(0, 32);
  const chunk1 = new Uint8Array(32);
  chunk1.set(b.slice(32, 48), 0);
  return merkleize([chunk0, chunk1]);
}

// Vector[BLSPubkey, 512]: BLSPubkey is composite, so elements are NOT
// packed together — each gets its own hash_tree_root leaf, then those 512
// leaves (already a power of 2) are merkleized.
function hashTreeRootPubkeysVector(pubkeys: string[]): Uint8Array {
  return merkleize(pubkeys.map(hashTreeRootBytes48));
}

function hashTreeRootSyncCommittee(pubkeys: string[], aggregatePubkey: string): Uint8Array {
  return merkleize([hashTreeRootPubkeysVector(pubkeys), hashTreeRootBytes48(aggregatePubkey)]);
}

// https://github.com/ethereum/consensus-specs/blob/master/ssz/merkle-proofs.md#merkle-multiproofs
function isValidMerkleBranch(leaf: Uint8Array, branch: Uint8Array[], depth: number, index: number, root: Uint8Array): boolean {
  let value = leaf;
  for (let i = 0; i < depth; i++) {
    const bit = (index >> i) & 1;
    value = bit === 1 ? sha256(branch[i]!, value) : sha256(value, branch[i]!);
  }
  return bytesToHex(value) === bytesToHex(root);
}

// get_generalized_index(BeaconState, 'current_sync_committee'): 54 through
// Altair (depth 5, i.e. 32<=54<64); the field shifted to 86 from Electra
// onward as BeaconState gained fields (depth 6, 64<=86<128) — frozen at
// that value for all forks after Electra per the light-client spec. Picking
// the wrong constant here doesn't crash anything, it just makes a REAL
// committee silently fail verification — worth stating plainly since it's
// exactly the kind of spec-version trap this step exists to not paper over.
// https://github.com/ethereum/consensus-specs/blob/dev/specs/electra/light-client/sync-protocol.md
const CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA = 86;

// --- Beacon API + SSZ Bitvector[512] decode

async function fetchJson(path: string): Promise<any> {
  const res = await fetch(`${BEACON_API}${path}`);
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status} ${await res.text()}`);
  return res.json();
}

function decodeParticipationBitmap(hex: string): number[] {
  const bytes = hexToBytes(hex);
  const indices: number[] = [];
  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i]!;
    for (let bit = 0; bit < 8; bit++) {
      if ((byte >> bit) & 1) indices.push(i * 8 + bit);
    }
  }
  return indices;
}

async function main() {
  console.error(`[probe] beacon API: ${BEACON_API}`);

  const genesis = (await fetchJson("/eth/v1/beacon/genesis")).data;
  const fork = (await fetchJson("/eth/v1/beacon/states/head/fork")).data;
  const finalizedRoot: string = (await fetchJson("/eth/v1/beacon/blocks/finalized/root")).data.root;

  console.error(`[probe] genesis_validators_root = ${genesis.genesis_validators_root}`);
  console.error(`[probe] current fork version    = ${fork.current_version} (active since epoch ${fork.epoch})`);

  const bootstrap = (await fetchJson(`/eth/v1/beacon/light_client/bootstrap/${finalizedRoot}`)).data;
  const committee = bootstrap.current_sync_committee;
  const branch: Uint8Array[] = bootstrap.current_sync_committee_branch.map(hexToBytes);
  console.error(`[probe] sync committee size     = ${committee.pubkeys.length} (expect 512)`);
  console.error(`[probe] committee merkle branch = ${branch.length} nodes`);

  const committeeRoot = hashTreeRootSyncCommittee(committee.pubkeys, committee.aggregate_pubkey);
  const stateRoot = bytes32Chunk(bootstrap.header.beacon.state_root);
  const committeeInState = isValidMerkleBranch(committeeRoot, branch, branch.length, CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA, stateRoot);
  console.error(`[probe] committee hash_tree_root = ${bytesToHex(committeeRoot)}`);
  console.error(`[probe] merkle branch verifies   = ${committeeInState} (proves committee is really IN beacon state ${bytesToHex(stateRoot)})`);
  if (!committeeInState) {
    console.error("[probe] FAILED — either the gindex constant is wrong for the current fork, or the SyncCommittee");
    console.error("[probe] hash_tree_root computation has a bug (see hashTreeRootSyncCommittee/hashTreeRootBytes48)");
    process.exit(1);
  }

  const update = (await fetchJson("/eth/v1/beacon/light_client/finality_update")).data;
  const attestedHeader: BeaconBlockHeader = update.attested_header.beacon;
  const bits = decodeParticipationBitmap(update.sync_aggregate.sync_committee_bits);
  console.error(`[probe] attested_header.slot    = ${attestedHeader.slot}`);
  console.error(`[probe] participation           = ${bits.length}/512 validators signed`);

  const domain = computeDomain(DOMAIN_SYNC_COMMITTEE, fork.current_version, genesis.genesis_validators_root);
  const objectRoot = hashTreeRootBeaconBlockHeader(attestedHeader);
  const signingRoot = computeSigningRoot(objectRoot, domain);
  console.error(`[probe] signing_root            = ${bytesToHex(signingRoot)}`);

  // Aggregate the REAL pubkeys of validators who actually participated —
  // bit i set in sync_committee_bits means committee.pubkeys[i] signed.
  const participatingPubkeys: Uint8Array[] = bits.map((i) => hexToBytes(committee.pubkeys[i]));
  const aggPubkey = bls12_381.longSignatures.aggregatePublicKeys(participatingPubkeys);

  const message = bls12_381.longSignatures.hash(signingRoot, POP_DST);
  const signatureBytes = hexToBytes(update.sync_aggregate.sync_committee_signature);
  const ok = bls12_381.longSignatures.verify(signatureBytes, message, aggPubkey);

  console.error(`[probe] BLS signature verifies  = ${ok}`);
  if (!ok) {
    console.error("[probe] FAILED — signing_root/domain computation likely has a bug, see the SSZ helpers above");
    process.exit(1);
  }

  console.error("\n[probe] Real Ethereum mainnet sync committee aggregate signature VERIFIED, entirely off-chain.");
  console.error("[probe] Real SSZ merkle proof VERIFIED: the committee is genuinely committed inside the beacon state.");
  console.error("[probe] Still open (PLAN.md Milestone 5): wire this real data path into");
  console.error("[probe] LightClientVerifierBLSGeneral.sol (currently still uses its own demo committee), and");
  console.error("[probe] a real 'trustless bootstrap' (this script trusts ONE public node's HTTP responses).");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
