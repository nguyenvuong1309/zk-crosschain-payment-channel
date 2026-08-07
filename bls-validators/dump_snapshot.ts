#!/usr/bin/env -S npx tsx
// FFI helper for contracts/test/LightClientVerifierBLSReal.t.sol — flattens
// the fields of real_sync_committee_snapshot.json a Solidity test needs
// into one JSON object with short, `vm.parseJson*`-friendly keys.
//
// Usage: npx tsx dump_snapshot.ts
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const snapshot = JSON.parse(fs.readFileSync(path.join(__dirname, "real_sync_committee_snapshot.json"), "utf8"));

console.log(
  JSON.stringify({
    pubkeysEip2537: snapshot.committee.pubkeysEip2537,
    bootstrapHeaderStateRoot: snapshot.bootstrapHeaderStateRoot,
    currentSyncCommitteeBranch: snapshot.currentSyncCommitteeBranch,
    pubkeysCompressed: snapshot.committee.pubkeysCompressed,
    aggregatePubkeyCompressed: snapshot.committee.aggregatePubkeyCompressed,
  })
);
