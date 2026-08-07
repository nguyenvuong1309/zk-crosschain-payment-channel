// Loads ABI + bytecode straight from Foundry's build output
// (contracts/out/<File>.sol/<Contract>.json) — avoids hand-copying ABIs or
// adding a separate artifact-export step. Run `forge build` in contracts/
// first.
import fs from "fs";
import path from "path";
import type { InterfaceAbi } from "ethers";

const CONTRACTS_OUT = path.join(__dirname, "..", "..", "contracts", "out");

export interface Artifact {
  abi: InterfaceAbi;
  bytecode: string;
}

function loadArtifact(fileName: string, contractName: string): Artifact {
  const artifactPath = path.join(CONTRACTS_OUT, `${fileName}.sol`, `${contractName}.json`);
  if (!fs.existsSync(artifactPath)) {
    throw new Error(`missing build artifact ${artifactPath} — run "forge build" in contracts/ first`);
  }
  const raw = JSON.parse(fs.readFileSync(artifactPath, "utf8"));
  return { abi: raw.abi, bytecode: raw.bytecode.object };
}

export function PaymentChannel(): Artifact {
  return loadArtifact("PaymentChannel", "PaymentChannel");
}
export function Groth16Verifier(): Artifact {
  return loadArtifact("Groth16Verifier", "Groth16Verifier");
}
export function Groth16VerifierConsensus(): Artifact {
  return loadArtifact("Groth16VerifierConsensus", "Groth16VerifierConsensus");
}
export function LightClientVerifier(): Artifact {
  return loadArtifact("LightClientVerifier", "LightClientVerifier");
}
