// Regenerates src/poseidon_constants_t{T}.rs from circomlibjs's Poseidon
// constants (BN254 Fr) — the SAME constants circomlib/channel_state.circom
// use, so this Halo2 Poseidon chip is byte-for-byte the same hash function,
// not a reimplementation with independently-chosen (and unaudited) constants.
//
// Usage (from circuits-halo2/): node scripts/extract_poseidon_constants.js
const raw = require("../../circuits/node_modules/circomlibjs/src/poseidon_constants_opt.json");
const fs = require("fs");
const path = require("path");

const N_ROUNDS_P_TABLE = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68];

function arr1(a) {
  return "&[" + a.map((x) => JSON.stringify(x)).join(", ") + "]";
}
function arr2(a) {
  return "&[" + a.map(arr1).join(", ") + "]";
}

function generate(t) {
  const idx = t - 2;
  const C = raw.C[idx];
  const S = raw.S[idx];
  const M = raw.M[idx];
  const P = raw.P[idx];
  const N_ROUNDS_P = N_ROUNDS_P_TABLE[idx];

  let out = `// Auto-generated from circomlibjs poseidon_constants_opt.json (t=${t}, BN254 Fr).\n`;
  out += "// DO NOT hand-edit — regenerate via scripts/extract_poseidon_constants.js.\n\n";
  out += `pub const N_ROUNDS_F: usize = 8;\n`;
  out += `pub const N_ROUNDS_P: usize = ${N_ROUNDS_P};\n`;
  out += `pub const T: usize = ${t};\n\n`;
  out += `pub const C: &[&str] = ${arr1(C)};\n\n`;
  out += `pub const S: &[&str] = ${arr1(S)};\n\n`;
  out += `pub const M: &[&[&str]] = ${arr2(M)};\n\n`;
  out += `pub const P: &[&[&str]] = ${arr2(P)};\n`;
  return out;
}

for (const t of [3, 6, 7]) {
  const out = generate(t);
  const dest = path.join(__dirname, "..", "src", `poseidon_constants_t${t}.rs`);
  fs.writeFileSync(dest, out);
  console.error(`wrote ${dest}`);
}
