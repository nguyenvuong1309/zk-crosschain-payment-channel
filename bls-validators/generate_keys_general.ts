#!/usr/bin/env -S npx tsx
// Milestone 5 step 3 (see PLAN.md) — generates a LARGER demo BLS12-381
// validator committee (default 512, matching Ethereum's real sync
// committee size) to test-drive LightClientVerifierBLSGeneral.sol's
// generalized 2/3-of-N quorum against something the toy 5-key committee
// (generate_keys.ts, keys.json) can't exercise: bitmap sizes >256 bits,
// deploy-time gas for registering hundreds of validators, aggregate-pubkey
// gas for large quorums.
//
// Deliberately a SEPARATE script/output file from generate_keys.ts/keys.json
// — that file's exact byte-for-byte reproducibility is itself asserted by
// bls-validators/test.ts, and NUM_VALIDATORS=5 there is what
// LightClientVerifierBLS.sol (the ORIGINAL Milestone 4 demo contract) still
// hardcodes; this script/its output must never change that.
//
// Seeds are `bls-validator-${i}`, same derivation as generate_keys.ts, so
// validators 0-4 of ANY size committee generated here are byte-identical to
// the 5-key demo committee — not load-bearing, just a nice consistency
// check that both scripts derive keys the same way.
//
// Usage: npx tsx generate_keys_general.ts [numValidators=512]

import crypto from "crypto";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { bls12_381 } from "@noble/curves/bls12-381.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const NUM_VALIDATORS = Number(process.argv[2] ?? 512);
if (!Number.isInteger(NUM_VALIDATORS) || NUM_VALIDATORS < 1) {
  throw new Error(`numValidators must be a positive integer, got ${process.argv[2]}`);
}

function fpHex(n: bigint): string {
  return n.toString(16).padStart(128, "0");
}

function g1Hex(point: { toAffine?: () => { x: bigint; y: bigint } } & { x?: bigint; y?: bigint }): string {
  const p = point.toAffine ? point.toAffine() : (point as { x: bigint; y: bigint });
  return "0x" + fpHex(p.x) + fpHex(p.y);
}

function deriveSecretKey(seed: string): bigint {
  const hash = crypto.createHash("sha256").update(seed).digest();
  const reduced = (BigInt("0x" + hash.toString("hex")) % (bls12_381.fields.Fr.ORDER - 1n)) + 1n;
  return reduced;
}

interface ValidatorKey {
  seed: string;
  secretKey: string;
  pubkey: string; // EIP-2537 encoding (128 bytes) — for LightClientVerifierBLSGeneral.sol's G1ADD precompile calls
  pubkeyCompressed: string; // standard 48-byte compressed encoding — the format REAL Ethereum SSZ data uses (see sync_committee_probe.ts), needed for hash_tree_root cross-checks
}

console.error(`Deriving ${NUM_VALIDATORS} demo validator keypairs...`);
const points = Array.from({ length: NUM_VALIDATORS }, (_, i) => {
  const seed = `bls-validator-${i}`;
  const scalar = deriveSecretKey(seed);
  const sk = Buffer.from(scalar.toString(16).padStart(64, "0"), "hex");
  const pub = bls12_381.longSignatures.getPublicKey(sk);
  return { seed, sk, pub };
});

const validators: ValidatorKey[] = points.map(({ seed, sk, pub }) => ({
  seed,
  secretKey: "0x" + sk.toString("hex"),
  pubkey: g1Hex(pub),
  pubkeyCompressed: "0x" + pub.toHex(true),
}));

// SSZ SyncCommittee.aggregate_pubkey semantics: the sum of EVERY committee
// member's pubkey (G1 point addition), NOT just whoever signed a given
// update — same field real Ethereum's bootstrap.data.current_sync_committee
// carries (see sync_committee_probe.ts). Needed to cross-check
// hashTreeRootSyncCommittee's on-chain (SSZ.sol) vs off-chain
// (sync_committee_probe.ts) implementations against this demo committee.
const aggregatePubkeyPoint = bls12_381.longSignatures.aggregatePublicKeys(points.map((p) => p.pub));
const aggregatePubkeyCompressed = "0x" + aggregatePubkeyPoint.toHex(true);

const negG1Generator = g1Hex(bls12_381.G1.Point.BASE.negate());

const out = {
  note: `Demo-only BLS12-381 validator committee, N=${NUM_VALIDATORS} (Milestone 5 step 3) — deterministically derived from fixed seeds (same scheme as generate_keys.ts/keys.json), NEVER use for real value. Exists to test LightClientVerifierBLSGeneral.sol's 2/3-of-N quorum at real Ethereum sync-committee scale.`,
  numValidators: NUM_VALIDATORS,
  threshold: Math.ceil((2 * NUM_VALIDATORS) / 3),
  validators,
  aggregatePubkeyCompressed,
  negG1Generator,
};

const outPath = path.join(__dirname, `keys_general_${NUM_VALIDATORS}.json`);
fs.writeFileSync(outPath, JSON.stringify(out, null, 2));

for (const v of validators) {
  if ((v.secretKey.length - 2) / 2 !== 32) throw new Error(`${v.seed}: secretKey wrong length`);
  if ((v.pubkey.length - 2) / 2 !== 128) throw new Error(`${v.seed}: pubkey wrong length`);
}
if ((negG1Generator.length - 2) / 2 !== 128) throw new Error("negG1Generator wrong length");

console.error(`Wrote ${outPath} (${NUM_VALIDATORS} validators, threshold ${out.threshold}, all lengths verified).`);
