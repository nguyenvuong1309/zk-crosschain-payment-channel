#!/usr/bin/env node
// End-to-end Milestone 3 demo: opens a channel on Chain A, moves it to a
// new agreed state (closeUnilateral — funds not withdrawn yet on Chain A on
// purpose, to show settlement on Chain B doesn't wait on Chain A's challenge
// window), relays that state to Chain B via the real relayer + a real
// consensus_proof.circom proof, opens a MATCHING channel on Chain B, settles
// it with closeWithRemoteAttestation, and withdraws — asserting Chain B's
// payout matches Chain A's attested state exactly, despite the two chains
// being completely independent EVMs.
//
// Prerequisites: both Anvil chains running (chains/start_chain_a.sh,
// chains/start_chain_b.sh) and `node src/deploy.js` already run.
//
// Usage: node src/e2e_demo.js

const path = require("path");
const { ethers } = require("ethers");
const artifacts = require("./artifacts");
const { relayChannelState, loadDeployment } = require("./index");

// Anvil's well-known default accounts #0/#1 — local demo only.
const PARTY_A_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PARTY_B_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";

const DEPOSIT_A = ethers.parseEther("1");
const DEPOSIT_B = ethers.parseEther("1");

async function signState(wallet, paymentChannel, state) {
  const digest = await paymentChannel.hashState(state);
  return wallet.signMessage(ethers.getBytes(digest));
}

async function assertEqual(label, actual, expected) {
  if (actual.toString() !== expected.toString()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
  console.error(`  OK  ${label} = ${actual}`);
}

async function main() {
  const deployment = loadDeployment(path.join(__dirname, "..", "deployment.json"));
  const { abi: paymentChannelAbi } = artifacts.PaymentChannel();

  const chainA = deployment.chains.chainA;
  const chainB = deployment.chains.chainB;

  const providerA = new ethers.JsonRpcProvider(chainA.rpcUrl);
  const providerB = new ethers.JsonRpcProvider(chainB.rpcUrl);
  // NonceManager: partyA/partyB each send several sequential txs on the
  // same chain, and ethers v6's default "pending"-tag nonce lookup was
  // observed to return a stale value when queried again immediately after
  // a prior send on the same provider instance (see
  // watchtower/src/e2e_demo.js and relayer/src/deploy.js for the same fix).
  const partyAOnA = new ethers.NonceManager(new ethers.Wallet(PARTY_A_KEY, providerA));
  const partyBOnA = new ethers.NonceManager(new ethers.Wallet(PARTY_B_KEY, providerA));
  const partyAOnB = new ethers.NonceManager(new ethers.Wallet(PARTY_A_KEY, providerB));
  const partyBOnB = new ethers.NonceManager(new ethers.Wallet(PARTY_B_KEY, providerB));
  // NonceManager has no sync `.address` — plain (unconnected) wallets just
  // for address lookups.
  const partyAAddress = new ethers.Wallet(PARTY_A_KEY).address;
  const partyBAddress = new ethers.Wallet(PARTY_B_KEY).address;

  const paymentChannelA = new ethers.Contract(chainA.paymentChannel, paymentChannelAbi, providerA);
  const paymentChannelB = new ethers.Contract(chainB.paymentChannel, paymentChannelAbi, providerB);

  console.error("--- Step 1: open + join a channel on Chain A ---");
  let tx = await paymentChannelA.connect(partyAOnA).open(partyBAddress, DEPOSIT_A, 0, 0, 0, 0, 0, { value: DEPOSIT_A });
  let receipt = await tx.wait();
  const openedEvent = receipt.logs.map((l) => paymentChannelA.interface.parseLog(l)).find((e) => e && e.name === "ChannelOpened");
  const channelId = openedEvent.args.channelId;
  console.error(`  channelId = ${channelId}`);

  tx = await paymentChannelA.connect(partyBOnA).join(channelId, 0, 0, 0, 0, 0, { value: DEPOSIT_B });
  await tx.wait();

  console.error("--- Step 2: move the channel to a new agreed state on Chain A (closeUnilateral) ---");
  const state = { channelId, nonce: 1, balanceA: ethers.parseEther("0.3"), balanceB: ethers.parseEther("1.7") };
  const sigA = await signState(partyAOnA, paymentChannelA, state);
  const sigB = await signState(partyBOnA, paymentChannelA, state);
  tx = await paymentChannelA.connect(partyAOnA).closeUnilateral(state, sigA, sigB);
  await tx.wait();
  console.error("  Chain A channel now in CHALLENGE_PERIOD with nonce=1, balanceA=0.3, balanceB=1.7 (funds NOT withdrawn yet)");

  console.error("--- Step 3: relay Chain A's state to Chain B's LightClientVerifier (real consensus proof) ---");
  const relayResult = await relayChannelState({ deployment, channelId: channelId.toString() });
  console.error(`  Chain B now trusts stateRoot=${relayResult.stateRoot} for Chain A`);

  console.error("--- Step 4: open a MATCHING channel on Chain B ---");
  tx = await paymentChannelB.connect(partyAOnB).open(partyBAddress, DEPOSIT_A, 0, 0, 0, 0, 0, { value: DEPOSIT_A });
  receipt = await tx.wait();
  const openedEventB = receipt.logs.map((l) => paymentChannelB.interface.parseLog(l)).find((e) => e && e.name === "ChannelOpened");
  const channelIdB = openedEventB.args.channelId;
  if (channelIdB.toString() !== channelId.toString()) {
    throw new Error(`channelId mismatch: Chain A=${channelId} Chain B=${channelIdB} (demo assumes matching ids)`);
  }
  tx = await paymentChannelB.connect(partyBOnB).join(channelIdB, 0, 0, 0, 0, 0, { value: DEPOSIT_B });
  await tx.wait();

  console.error("--- Step 5: settle Chain B's channel via closeWithRemoteAttestation ---");
  tx = await paymentChannelB
    .connect(partyAOnB)
    .closeWithRemoteAttestation(channelIdB, chainA.paymentChannel, chainA.chainId, state);
  await tx.wait();
  console.error("  Chain B channel now in CHALLENGE_PERIOD with the SAME state, via a validator-attested proof — no bridge/asset transfer");

  console.error("--- Step 6: wait out Chain B's challenge window and withdraw ---");
  // CHALLENGE_PERIOD is 1 day — advance Chain B's clock (anvil-only RPC).
  await providerB.send("evm_increaseTime", [24 * 60 * 60 + 1]);
  await providerB.send("evm_mine", []);

  // Fresh provider instances for these balance snapshots — reusing
  // `providerB` for rapid sequential eth_getBalance calls was observed to
  // return stale values against Anvil (same class of issue as the nonce
  // staleness noted above for NonceManager).
  const balABefore = await new ethers.JsonRpcProvider(chainB.rpcUrl).getBalance(partyAAddress);
  const balBBefore = await new ethers.JsonRpcProvider(chainB.rpcUrl).getBalance(partyBAddress);

  tx = await paymentChannelB.connect(partyBOnB).withdraw(channelIdB);
  const withdrawReceipt = await tx.wait();
  const gasCost = withdrawReceipt.gasUsed * withdrawReceipt.gasPrice;

  const balAAfter = await new ethers.JsonRpcProvider(chainB.rpcUrl).getBalance(partyAAddress);
  const balBAfter = await new ethers.JsonRpcProvider(chainB.rpcUrl).getBalance(partyBAddress);

  console.error("--- Verifying Chain B payouts match Chain A's attested state ---");
  await assertEqual("partyA payout on Chain B", balAAfter - balABefore, state.balanceA);
  // partyB paid this tx's gas out of the same balance being checked — add it back.
  await assertEqual("partyB payout on Chain B (net of its own withdraw() gas)", balBAfter - balBBefore + gasCost, state.balanceB);

  console.error("\nEnd-to-end cross-chain settle succeeded: Chain A's channel state (0.3/1.7 ETH), reached via a");
  console.error("real consensus_proof.circom proof + LightClientVerifier, produced an identical payout on Chain B.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
