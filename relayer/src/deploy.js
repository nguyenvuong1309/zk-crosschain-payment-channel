#!/usr/bin/env node
// Deploys everything Milestone 3 needs onto the two local Anvil chains
// (see chains/start_chain_a.sh / start_chain_b.sh):
//
//   Chain A: Groth16Verifier, PaymentChannel(channelStateVerifier, noLightClient)
//   Chain B: Groth16Verifier, Groth16VerifierConsensus, LightClientVerifier,
//            PaymentChannel(channelStateVerifier, lightClientVerifier)
//
// Only Chain B needs a light client here — Milestone 3's demo flow relays
// ONE direction (a channel's final state on Chain A gets attested and
// settled on Chain B, see PLAN.md Milestone 3). Chain A's PaymentChannel is
// deployed with lightClientVerifier = address(0) (see
// PaymentChannel.sol's constructor doc).
//
// Writes addresses to deployment.json (gitignored) so the relayer and the
// e2e demo script can find everything without re-deploying.
//
// Usage: node src/deploy.js [--out deployment.json]

const path = require("path");
const fs = require("fs");
const { ethers } = require("ethers");
const artifacts = require("./artifacts");

const CHAIN_A_RPC = process.env.CHAIN_A_RPC ?? "http://127.0.0.1:8545";
const CHAIN_B_RPC = process.env.CHAIN_B_RPC ?? "http://127.0.0.1:8546";

// Anvil's well-known default account #0 private key — local demo only.
const DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

async function deployContract(wallet, { abi, bytecode }, args = []) {
  const factory = new ethers.ContractFactory(abi, bytecode, wallet);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

async function main() {
  const outArg = process.argv.includes("--out") ? process.argv[process.argv.indexOf("--out") + 1] : "deployment.json";
  const outPath = path.join(__dirname, "..", outArg);

  const providerA = new ethers.JsonRpcProvider(CHAIN_A_RPC);
  const providerB = new ethers.JsonRpcProvider(CHAIN_B_RPC);
  const walletA = new ethers.Wallet(DEPLOYER_KEY, providerA);
  const walletB = new ethers.Wallet(DEPLOYER_KEY, providerB);

  const chainAId = (await providerA.getNetwork()).chainId;
  const chainBId = (await providerB.getNetwork()).chainId;

  console.error(`Deploying to Chain A (chainId=${chainAId}, ${CHAIN_A_RPC})...`);
  const channelStateVerifierA = await deployContract(walletA, artifacts.Groth16Verifier());
  const paymentChannelA = await deployContract(walletA, artifacts.PaymentChannel(), [
    await channelStateVerifierA.getAddress(),
    ethers.ZeroAddress,
  ]);
  console.error(`  Groth16Verifier:  ${await channelStateVerifierA.getAddress()}`);
  console.error(`  PaymentChannel:   ${await paymentChannelA.getAddress()}`);

  console.error(`Deploying to Chain B (chainId=${chainBId}, ${CHAIN_B_RPC})...`);
  const channelStateVerifierB = await deployContract(walletB, artifacts.Groth16Verifier());
  const consensusVerifierB = await deployContract(walletB, artifacts.Groth16VerifierConsensus());
  const lightClientB = await deployContract(walletB, artifacts.LightClientVerifier(), [await consensusVerifierB.getAddress()]);
  const paymentChannelB = await deployContract(walletB, artifacts.PaymentChannel(), [
    await channelStateVerifierB.getAddress(),
    await lightClientB.getAddress(),
  ]);
  console.error(`  Groth16Verifier:          ${await channelStateVerifierB.getAddress()}`);
  console.error(`  Groth16VerifierConsensus: ${await consensusVerifierB.getAddress()}`);
  console.error(`  LightClientVerifier:      ${await lightClientB.getAddress()}`);
  console.error(`  PaymentChannel:           ${await paymentChannelB.getAddress()}`);

  const deployment = {
    chainA: { rpcUrl: CHAIN_A_RPC, chainId: chainAId.toString(), paymentChannel: await paymentChannelA.getAddress() },
    chainB: {
      rpcUrl: CHAIN_B_RPC,
      chainId: chainBId.toString(),
      paymentChannel: await paymentChannelB.getAddress(),
      lightClientVerifier: await lightClientB.getAddress(),
    },
  };
  fs.writeFileSync(outPath, JSON.stringify(deployment, null, 2));
  console.error(`Wrote ${outPath}`);
  console.log(JSON.stringify(deployment));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
