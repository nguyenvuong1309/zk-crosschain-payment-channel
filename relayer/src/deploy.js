#!/usr/bin/env node
// Deploys PaymentChannel (+ LightClientVerifier where configured) onto
// every chain listed in chains.config.json — local Anvil by default (see
// chains/start_chain_a.sh / start_chain_b.sh), or any real network (e.g. a
// public testnet) via .env — see .env.example.
//
// For each chain:
//   Groth16Verifier, PaymentChannel(channelStateVerifier, lightClientVerifier?)
//   + if the chain's config sets "lightClient": true, also:
//     Groth16VerifierConsensus, LightClientVerifier(consensusVerifier)
//
// Which chains get a light client (i.e. which chains can accept remote-
// attested state from another chain) is a property of chains.config.json,
// not of this script — add a chain there, decide its lightClient flag, and
// this script deploys it correctly with zero code changes. See
// relayer/src/chains.js.
//
// Writes addresses to deployment.json (gitignored) so the relayer and the
// e2e demo script can find everything without re-deploying.
//
// Usage: node src/deploy.js [--out deployment.json]

require("dotenv").config();
const path = require("path");
const fs = require("fs");
const { ethers } = require("ethers");
const artifacts = require("./artifacts");
const { resolveChains } = require("./chains");

async function deployContract(wallet, { abi, bytecode }, args = []) {
  const factory = new ethers.ContractFactory(abi, bytecode, wallet);
  const contract = await factory.deploy(...args);
  await contract.waitForDeployment();
  return contract;
}

/// Deploys one chain's contracts. Returns the addresses to record in
/// deployment.json for this chain name.
async function deployChain(name, { rpcUrl, deployerKey, lightClient }) {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  // NonceManager: each chain does several sequential deploys from the same
  // wallet, and ethers v6's default "pending"-tag nonce lookup was observed
  // to return a stale value when queried again immediately after a prior
  // send on the same provider instance (same issue worked around in
  // watchtower/src/e2e_demo.js — see its comment for more detail).
  const wallet = new ethers.NonceManager(new ethers.Wallet(deployerKey, provider));
  const chainId = (await provider.getNetwork()).chainId;

  console.error(`Deploying to ${name} (chainId=${chainId}, ${rpcUrl}) from ${await wallet.getAddress()}...`);

  const channelStateVerifier = await deployContract(wallet, artifacts.Groth16Verifier());
  console.error(`  Groth16Verifier:          ${await channelStateVerifier.getAddress()}`);

  let lightClientAddress = ethers.ZeroAddress;
  const record = { rpcUrl, chainId: chainId.toString() };

  if (lightClient) {
    const consensusVerifier = await deployContract(wallet, artifacts.Groth16VerifierConsensus());
    const lightClientContract = await deployContract(wallet, artifacts.LightClientVerifier(), [await consensusVerifier.getAddress()]);
    lightClientAddress = await lightClientContract.getAddress();
    console.error(`  Groth16VerifierConsensus: ${await consensusVerifier.getAddress()}`);
    console.error(`  LightClientVerifier:      ${lightClientAddress}`);
    record.lightClientVerifier = lightClientAddress;
  }

  const paymentChannel = await deployContract(wallet, artifacts.PaymentChannel(), [await channelStateVerifier.getAddress(), lightClientAddress]);
  console.error(`  PaymentChannel:           ${await paymentChannel.getAddress()}`);
  record.paymentChannel = await paymentChannel.getAddress();

  return record;
}

async function main() {
  const outArg = process.argv.includes("--out") ? process.argv[process.argv.indexOf("--out") + 1] : "deployment.json";
  const outPath = path.join(__dirname, "..", outArg);

  const chains = resolveChains();
  const deployment = { chains: {} };

  // Sequential, not Promise.all — deploys from the same wallet on the same
  // chain must not race (see NonceManager note above); across DIFFERENT
  // chains it's safe to parallelize, but sequential keeps log output
  // readable and this isn't performance-sensitive tooling.
  for (const [name, cfg] of Object.entries(chains)) {
    deployment.chains[name] = await deployChain(name, cfg);
  }

  fs.writeFileSync(outPath, JSON.stringify(deployment, null, 2));
  console.error(`Wrote ${outPath}`);
  console.log(JSON.stringify(deployment));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
