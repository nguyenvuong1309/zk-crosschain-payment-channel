// Relayer — Milestone 3 (see PLAN.md).
//
// Responsibilities:
//   1. Read a channel's current final state from the source chain's
//      PaymentChannel.
//   2. Compute the SAME domain-separated state hash
//      PaymentChannel.closeWithRemoteAttestation checks on the destination
//      chain (see that function's doc comment) — this is the `stateRoot`
//      the demo validator committee is asked to attest to.
//   3. Generate a consensus_proof.circom proof (shells out to
//      circuits/scripts/prove_and_export_consensus.sh — see that script and
//      prove_and_export.sh for why a CLI pipeline is used instead of
//      snarkjs's JS `groth16.fullProve` API).
//   4. Submit { proof, publicSignals } to the destination chain's
//      LightClientVerifier, updating its `trustedStateRoot[sourceChainId]`.
//
// Source/destination are chain NAMES from chains.config.json (see
// relayer/src/chains.js), not hardcoded chainA/chainB — this only relays
// one direction per call, but which two chains that is comes from the CLI
// args / deployment.json, so adding a 3rd chain never requires editing this
// file.
//
// This component only affects LIVENESS (see docs/threat-model.md #7): a
// crashed or malicious relayer delays cross-chain settlement, but the
// consensus proof it submits cryptographically requires a real quorum of
// (demo) validator signatures — it can never forge an attestation, so it
// can't steal funds or settle a channel to a state that wasn't actually
// signed off. See docs/threat-model.md #6 for why the validator committee
// itself is a demo/toy one, not a stand-in for real chain security.

require("dotenv").config();
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

/// Reads channelId's current state from `fromChain`, generates a consensus
/// proof attesting to it, and submits it to `toChain`'s LightClientVerifier.
/// `fromChain`/`toChain` are names in `deployment.chains` (see
/// relayer/src/chains.js + deploy.js) — `toChain` must have been deployed
/// with a light client. Returns the computed stateRoot and the submission
/// tx receipt.
async function relayChannelState({ deployment, channelId, fromChain = "chainA", toChain = "chainB" }) {
  const source = deployment.chains[fromChain];
  const dest = deployment.chains[toChain];
  if (!source) throw new Error(`unknown source chain "${fromChain}" — not in deployment.json's chains`);
  if (!dest) throw new Error(`unknown destination chain "${toChain}" — not in deployment.json's chains`);
  if (!dest.lightClientVerifier) {
    throw new Error(`destination chain "${toChain}" has no lightClientVerifier — redeploy it with "lightClient": true in chains.config.json`);
  }

  const providerSource = new ethers.JsonRpcProvider(source.rpcUrl);
  const providerDest = new ethers.JsonRpcProvider(dest.rpcUrl);

  const { abi: paymentChannelAbi } = artifacts.PaymentChannel();
  const { abi: lightClientAbi } = artifacts.LightClientVerifier();

  const paymentChannelSource = new ethers.Contract(source.paymentChannel, paymentChannelAbi, providerSource);
  const ch = await paymentChannelSource.channels(channelId);
  // ethers v6 returns uint256 struct fields as native bigint already.
  const nonce = ch.nonce;
  const balanceA = ch.balanceA;
  const balanceB = ch.balanceB;

  const stateRoot = computeRemoteStateHash({
    remoteContract: source.paymentChannel,
    remoteChainId: BigInt(source.chainId),
    channelId: BigInt(channelId),
    nonce,
    balanceA,
    balanceB,
  });

  const blockNumber = BigInt(await providerSource.getBlockNumber());

  console.error(
    `Relaying channel ${channelId} from ${fromChain} to ${toChain}: nonce=${nonce} balanceA=${balanceA} balanceB=${balanceB} ` +
      `(${fromChain} block ${blockNumber}) -> stateRoot=${stateRoot}`
  );

  const { a, b, c, pubSignals } = generateConsensusProof({ chainId: source.chainId, blockNumber, stateRoot });

  // Any FUNDED account works — updateState() has no access control (the
  // proof itself is what's trusted, see LightClientVerifier.sol's doc
  // comment). Falls back to Anvil's default account #1 for the local demo;
  // set RELAYER_PRIVATE_KEY in .env for anything else (a real testnet in
  // particular — see .env.example).
  const relayerKey = process.env.RELAYER_PRIVATE_KEY ?? "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
  const walletDest = new ethers.Wallet(relayerKey, providerDest);
  const lightClient = new ethers.Contract(dest.lightClientVerifier, lightClientAbi, walletDest);

  const tx = await lightClient.updateState(a, b, c, pubSignals);
  const receipt = await tx.wait();

  console.error(`Submitted to ${toChain}'s LightClientVerifier: tx ${receipt.hash}`);

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
  const fromChain = process.argv[3] ?? "chainA";
  const toChain = process.argv[4] ?? "chainB";
  if (channelId === undefined) {
    throw new Error("usage: node src/index.js <channelId> [fromChain=chainA] [toChain=chainB]  (relays that channel's current state once)");
  }

  const deployment = loadDeployment(deploymentPath);
  const result = await relayChannelState({ deployment, channelId, fromChain, toChain });
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
