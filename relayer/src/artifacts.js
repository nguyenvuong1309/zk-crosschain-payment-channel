// Loads ABI + bytecode straight from Foundry's build output
// (contracts/out/<File>.sol/<Contract>.json) — avoids hand-copying ABIs or
// adding a separate artifact-export step. Run `forge build` in contracts/
// first.
const fs = require("fs");
const path = require("path");

const CONTRACTS_OUT = path.join(__dirname, "..", "..", "contracts", "out");

function loadArtifact(fileName, contractName) {
  const artifactPath = path.join(CONTRACTS_OUT, `${fileName}.sol`, `${contractName}.json`);
  if (!fs.existsSync(artifactPath)) {
    throw new Error(`missing build artifact ${artifactPath} — run "forge build" in contracts/ first`);
  }
  const raw = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  return { abi: raw.abi, bytecode: raw.bytecode.object };
}

module.exports = {
  PaymentChannel: () => loadArtifact("PaymentChannel", "PaymentChannel"),
  Groth16Verifier: () => loadArtifact("Groth16Verifier", "Groth16Verifier"),
  Groth16VerifierConsensus: () => loadArtifact("Groth16VerifierConsensus", "Groth16VerifierConsensus"),
  LightClientVerifier: () => loadArtifact("LightClientVerifier", "LightClientVerifier"),
};
