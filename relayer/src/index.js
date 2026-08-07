// Relayer — Milestone 3 (see PLAN.md).
//
// Responsibilities:
//   1. Read a channel's current final state from Chain A's PaymentChannel.
//   2. Compute the SAME domain-separated state hash
//      PaymentChannel.closeWithRemoteAttestation checks on Chain B (see that
//      function's doc comment) — this is the `stateRoot` the demo validator
//      committee is asked to attest to.
//   3. Generate a consensus_proof.circom proof (shells out to
//      circuits/scripts/prove_and_export_consensus.sh — see that script and
//      prove_and_export.sh for why a CLI pipeline is used instead of
//      snarkjs's JS `groth16.fullProve` API).
//   4. Submit { proof, publicSignals } to Chain B's LightClientVerifier,
//      updating its `trustedStateRoot[chainA]`.
//
// This component only affects LIVENESS (see docs/threat-model.md #7): a
// crashed or malicious relayer delays cross-chain settlement, but the
// consensus proof it submits cryptographically requires a real quorum of
// (demo) validator signatures — it can never forge an attestation, so it
// can't steal funds or settle a channel to a state that wasn't actually
// signed off. See docs/threat-model.md #6 for why the validator committee
// itself is a demo/toy one, not a stand-in for real chain security.

const path = require("path");
const fs = require("fs");
const { execFileSync } = require("child_process");
const { ethers } = require("ethers");
const artifacts = require("./artifacts");

const CIRCUITS_SCRIPT = path.join(__dirname, "..", "..", "circuits", "scripts", "prove_and_export_consensus.sh");

// BN254 scalar field — must match BabyJubJub.Q in contracts/src/BabyJubJub.sol
// and consensus_proof.circom's field. See PaymentChannel.closeWithRemoteAttestation.
const FIELD_Q = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/// Mirrors PaymentChannel.sol::closeWithRemoteAttestation's
/// `remoteStateHash` computation exactly — see its doc comment.
function computeRemoteStateHash({ remoteContract, remoteChainId, channelId, nonce, balanceA, balanceB }) {
  const encoded = ethers.AbiCoder.defaultAbiCoder().encode(
    ["address", "uint256", "uint256", "uint256", "uint256", "uint256"],
    [remoteContract, remoteChainId, channelId, nonce, balanceA, balanceB]
  );
  const hash = BigInt(ethers.keccak256(encoded));
  return hash % FIELD_Q;
}

function generateConsensusProof({ chainId, blockNumber, stateRoot }) {
  const raw = execFileSync("bash", [CIRCUITS_SCRIPT, chainId.toString(), blockNumber.toString(), stateRoot.toString()], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
  });
  const { a, b0, b1, c, pubSignals } = JSON.parse(raw);
  return { a, b: [b0, b1], c, pubSignals };
}

/// Reads channelId's current state from Chain A, generates a consensus
/// proof attesting to it, and submits it to Chain B's LightClientVerifier.
/// Returns the computed stateRoot and the submission tx receipt.
async function relayChannelState({ deployment, channelId }) {
  const providerA = new ethers.JsonRpcProvider(deployment.chainA.rpcUrl);
  const providerB = new ethers.JsonRpcProvider(deployment.chainB.rpcUrl);

  const { abi: paymentChannelAbi } = artifacts.PaymentChannel();
  const { abi: lightClientAbi } = artifacts.LightClientVerifier();

  const paymentChannelA = new ethers.Contract(deployment.chainA.paymentChannel, paymentChannelAbi, providerA);
  const ch = await paymentChannelA.channels(channelId);
  // ethers v6 returns uint256 struct fields as native bigint already.
  const nonce = ch.nonce;
  const balanceA = ch.balanceA;
  const balanceB = ch.balanceB;

  const stateRoot = computeRemoteStateHash({
    remoteContract: deployment.chainA.paymentChannel,
    remoteChainId: BigInt(deployment.chainA.chainId),
    channelId: BigInt(channelId),
    nonce,
    balanceA,
    balanceB,
  });

  const blockNumber = BigInt(await providerA.getBlockNumber());

  console.error(
    `Relaying channel ${channelId}: nonce=${nonce} balanceA=${balanceA} balanceB=${balanceB} ` +
      `(Chain A block ${blockNumber}) -> stateRoot=${stateRoot}`
  );

  const { a, b, c, pubSignals } = generateConsensusProof({ chainId: deployment.chainA.chainId, blockNumber, stateRoot });

  // Anvil default account #1 — any funded account works, updateState() has
  // no access control (the proof itself is what's trusted, see
  // LightClientVerifier.sol's doc comment).
  const relayerKey = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
  const walletB = new ethers.Wallet(relayerKey, providerB);
  const lightClient = new ethers.Contract(deployment.chainB.lightClientVerifier, lightClientAbi, walletB);

  const tx = await lightClient.updateState(a, b, c, pubSignals);
  const receipt = await tx.wait();

  console.error(`Submitted to Chain B LightClientVerifier: tx ${receipt.hash}`);

  return { stateRoot, nonce, balanceA, balanceB, txHash: receipt.hash };
}

function loadDeployment(deploymentPath) {
  if (!fs.existsSync(deploymentPath)) {
    throw new Error(`no deployment file at ${deploymentPath} — run "node src/deploy.js" first`);
  }
  return JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
}

async function main() {
  const deploymentPath = process.env.DEPLOYMENT_FILE ?? path.join(__dirname, "..", "deployment.json");
  const channelId = process.argv[2];
  if (channelId === undefined) {
    throw new Error("usage: node src/index.js <channelId>  (relays that channel's current state Chain A -> Chain B once)");
  }

  const deployment = loadDeployment(deploymentPath);
  const result = await relayChannelState({ deployment, channelId });
  console.log(
    JSON.stringify({
      ...result,
      nonce: result.nonce.toString(),
      balanceA: result.balanceA.toString(),
      balanceB: result.balanceB.toString(),
      stateRoot: result.stateRoot.toString(),
    })
  );
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { relayChannelState, computeRemoteStateHash, generateConsensusProof, loadDeployment };
