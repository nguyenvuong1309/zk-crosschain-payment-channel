#!/usr/bin/env -S npx tsx
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
// chains/start_chain_b.sh) and `npx tsx src/deploy.ts` already run.
//
// Usage: npx tsx src/e2e_demo.ts

import path from "path";
import { ethers, type Contract, type Signer } from "ethers";
import * as artifacts from "./artifacts";
import { relayChannelState, loadDeployment } from "./index";

// Anvil's well-known default accounts #0/#1 — local demo only.
const PARTY_A_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PARTY_B_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
// relayChannelState() defaults RELAYER_PRIVATE_KEY to this SAME value as
// PARTY_B_KEY (see index.ts) when unset — fine for a ONE-directional relay,
// but this demo relays BOTH directions, and partyB already has its own
// NonceManager-tracked wallet(s) on both chains (partyBOnA/partyBOnB
// below). Reusing partyB's key for the out-of-band relay tx too means that
// tx's nonce is invisible to whichever NonceManager was created for partyB
// on the DESTINATION chain, desyncing it from the chain's real nonce for
// every send after — hit exactly this running Part 2 below (Chain B->A)
// while writing this demo: partyBOnA's cached nonce went stale the moment
// the B->A relay tx (from the same key, but a separate plain wallet,
// bypassing partyBOnA's NonceManager entirely) landed on chain A first.
// Anvil's well-known account #2 — distinct from both parties — sidesteps
// this by construction, not by getting lucky with ordering (Part 1 above
// happened not to hit it only because partyBOnB's first-ever send came
// AFTER that direction's relay tx).
const RELAYER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
process.env.RELAYER_PRIVATE_KEY = RELAYER_KEY;

const DEPOSIT_A = ethers.parseEther("1");
const DEPOSIT_B = ethers.parseEther("1");

interface ChannelState {
  channelId: bigint;
  nonce: number;
  balanceA: bigint;
  balanceB: bigint;
}

async function signState(wallet: Signer, paymentChannel: Contract, state: ChannelState): Promise<string> {
  const digest: string = await paymentChannel.hashState!(state);
  return wallet.signMessage(ethers.getBytes(digest));
}

async function assertEqual(label: string, actual: bigint, expected: bigint): Promise<void> {
  if (actual.toString() !== expected.toString()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
  console.error(`  OK  ${label} = ${actual}`);
}

async function main() {
  const deployment = loadDeployment(path.join(__dirname, "..", "deployment.json"));
  const { abi: paymentChannelAbi } = artifacts.PaymentChannel();

  const chainA = deployment.chains.chainA!;
  const chainB = deployment.chains.chainB!;

  const providerA = new ethers.JsonRpcProvider(chainA.rpcUrl);
  const providerB = new ethers.JsonRpcProvider(chainB.rpcUrl);
  // NonceManager: partyA/partyB each send several sequential txs on the
  // same chain, and ethers v6's default "pending"-tag nonce lookup was
  // observed to return a stale value when queried again immediately after
  // a prior send on the same provider instance (see
  // watchtower/src/e2e_demo.ts and relayer/src/deploy.ts for the same fix).
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
  let tx = await (paymentChannelA.connect(partyAOnA) as Contract).open!(partyBAddress, DEPOSIT_A, 0, 0, 0, 0, 0, { value: DEPOSIT_A });
  let receipt = await tx.wait();
  const openedEvent = receipt.logs.map((l: any) => paymentChannelA.interface.parseLog(l)).find((e: any) => e && e.name === "ChannelOpened");
  const channelId: bigint = openedEvent.args.channelId;
  console.error(`  channelId = ${channelId}`);

  tx = await (paymentChannelA.connect(partyBOnA) as Contract).join!(channelId, 0, 0, 0, 0, 0, { value: DEPOSIT_B });
  await tx.wait();

  console.error("--- Step 2: move the channel to a new agreed state on Chain A (closeUnilateral) ---");
  const state: ChannelState = { channelId, nonce: 1, balanceA: ethers.parseEther("0.3"), balanceB: ethers.parseEther("1.7") };
  const sigA = await signState(partyAOnA, paymentChannelA, state);
  const sigB = await signState(partyBOnA, paymentChannelA, state);
  tx = await (paymentChannelA.connect(partyAOnA) as Contract).closeUnilateral!(state, sigA, sigB);
  await tx.wait();
  console.error("  Chain A channel now in CHALLENGE_PERIOD with nonce=1, balanceA=0.3, balanceB=1.7 (funds NOT withdrawn yet)");

  console.error("--- Step 3: relay Chain A's state to Chain B's LightClientVerifier (real consensus proof) ---");
  const relayResult = await relayChannelState({ deployment, channelId: channelId.toString() });
  console.error(`  Chain B now trusts stateRoot=${relayResult.stateRoot} for Chain A`);

  console.error("--- Step 4: open a MATCHING channel on Chain B ---");
  tx = await (paymentChannelB.connect(partyAOnB) as Contract).open!(partyBAddress, DEPOSIT_A, 0, 0, 0, 0, 0, { value: DEPOSIT_A });
  receipt = await tx.wait();
  const openedEventB = receipt.logs.map((l: any) => paymentChannelB.interface.parseLog(l)).find((e: any) => e && e.name === "ChannelOpened");
  const channelIdB: bigint = openedEventB.args.channelId;
  if (channelIdB.toString() !== channelId.toString()) {
    throw new Error(`channelId mismatch: Chain A=${channelId} Chain B=${channelIdB} (demo assumes matching ids)`);
  }
  tx = await (paymentChannelB.connect(partyBOnB) as Contract).join!(channelIdB, 0, 0, 0, 0, 0, { value: DEPOSIT_B });
  await tx.wait();

  console.error("--- Step 5: settle Chain B's channel via closeWithRemoteAttestation ---");
  tx = await (paymentChannelB.connect(partyAOnB) as Contract).closeWithRemoteAttestation!(channelIdB, chainA.paymentChannel, chainA.chainId, state);
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

  tx = await (paymentChannelB.connect(partyBOnB) as Contract).withdraw!(channelIdB);
  const withdrawReceipt = await tx.wait();
  const gasCost: bigint = BigInt(withdrawReceipt.gasUsed) * BigInt(withdrawReceipt.gasPrice);

  const balAAfter = await new ethers.JsonRpcProvider(chainB.rpcUrl).getBalance(partyAAddress);
  const balBAfter = await new ethers.JsonRpcProvider(chainB.rpcUrl).getBalance(partyBAddress);

  console.error("--- Verifying Chain B payouts match Chain A's attested state ---");
  await assertEqual("partyA payout on Chain B", balAAfter - balABefore, state.balanceA);
  // partyB paid this tx's gas out of the same balance being checked — add it back.
  await assertEqual("partyB payout on Chain B (net of its own withdraw() gas)", balBAfter - balBBefore + gasCost, state.balanceB);

  console.error("\nChain A -> Chain B settle succeeded: Chain A's channel state (0.3/1.7 ETH), reached via a real");
  console.error("consensus_proof.circom proof + LightClientVerifier, produced an identical payout on Chain B.");

  // ---------------------------------------------------------------------
  // Part 2: the SAME mechanism, the OTHER direction — Chain B -> Chain A.
  // Proves this isn't just "the relayer's fromChain/toChain params are
  // flexible" but that chainA genuinely has its own LightClientVerifier
  // and can accept remote-attested state, exactly as chainB does above
  // (see chains.config.json — both chains set "lightClient": true).
  // ---------------------------------------------------------------------
  console.error("\n=== Part 2: relaying Chain B -> Chain A (the reverse direction) ===");

  console.error("--- Step 7: open + join a SECOND channel on Chain B ---");
  tx = await (paymentChannelB.connect(partyAOnB) as Contract).open!(partyBAddress, DEPOSIT_A, 0, 0, 0, 0, 0, { value: DEPOSIT_A });
  receipt = await tx.wait();
  const openedEventB2 = receipt.logs.map((l: any) => paymentChannelB.interface.parseLog(l)).find((e: any) => e && e.name === "ChannelOpened");
  const channelIdB2: bigint = openedEventB2.args.channelId;
  console.error(`  Chain B channelId = ${channelIdB2}`);
  tx = await (paymentChannelB.connect(partyBOnB) as Contract).join!(channelIdB2, 0, 0, 0, 0, 0, { value: DEPOSIT_B });
  await tx.wait();

  console.error("--- Step 8: move THIS channel to a new agreed state on Chain B ---");
  const stateB: ChannelState = { channelId: channelIdB2, nonce: 1, balanceA: ethers.parseEther("0.9"), balanceB: ethers.parseEther("1.1") };
  const sigAonB = await signState(partyAOnB, paymentChannelB, stateB);
  const sigBonB = await signState(partyBOnB, paymentChannelB, stateB);
  tx = await (paymentChannelB.connect(partyAOnB) as Contract).closeUnilateral!(stateB, sigAonB, sigBonB);
  await tx.wait();
  console.error("  Chain B channel now in CHALLENGE_PERIOD with nonce=1, balanceA=0.9, balanceB=1.1 (funds NOT withdrawn yet)");

  console.error("--- Step 9: relay Chain B's state to Chain A's LightClientVerifier (real consensus proof, REVERSE direction) ---");
  const relayResultBA = await relayChannelState({ deployment, channelId: channelIdB2.toString(), fromChain: "chainB", toChain: "chainA" });
  console.error(`  Chain A now trusts stateRoot=${relayResultBA.stateRoot} for Chain B`);

  console.error("--- Step 10: open a MATCHING channel on Chain A and settle via closeWithRemoteAttestation ---");
  tx = await (paymentChannelA.connect(partyAOnA) as Contract).open!(partyBAddress, DEPOSIT_A, 0, 0, 0, 0, 0, { value: DEPOSIT_A });
  receipt = await tx.wait();
  const openedEventA2 = receipt.logs.map((l: any) => paymentChannelA.interface.parseLog(l)).find((e: any) => e && e.name === "ChannelOpened");
  const channelIdA2: bigint = openedEventA2.args.channelId;
  if (channelIdA2.toString() !== channelIdB2.toString()) {
    throw new Error(`channelId mismatch: Chain A=${channelIdA2} Chain B=${channelIdB2} (demo assumes matching ids)`);
  }
  tx = await (paymentChannelA.connect(partyBOnA) as Contract).join!(channelIdA2, 0, 0, 0, 0, 0, { value: DEPOSIT_B });
  await tx.wait();

  tx = await (paymentChannelA.connect(partyAOnA) as Contract).closeWithRemoteAttestation!(channelIdA2, chainB.paymentChannel, chainB.chainId, stateB);
  await tx.wait();
  console.error("  Chain A channel now in CHALLENGE_PERIOD with the SAME state, attested FROM Chain B this time");

  console.error("--- Step 11: wait out Chain A's challenge window and withdraw ---");
  await providerA.send("evm_increaseTime", [24 * 60 * 60 + 1]);
  await providerA.send("evm_mine", []);

  const balABeforeA = await new ethers.JsonRpcProvider(chainA.rpcUrl).getBalance(partyAAddress);
  const balBBeforeA = await new ethers.JsonRpcProvider(chainA.rpcUrl).getBalance(partyBAddress);

  tx = await (paymentChannelA.connect(partyBOnA) as Contract).withdraw!(channelIdA2);
  const withdrawReceiptA = await tx.wait();
  const gasCostA: bigint = BigInt(withdrawReceiptA.gasUsed) * BigInt(withdrawReceiptA.gasPrice);

  const balAAfterA = await new ethers.JsonRpcProvider(chainA.rpcUrl).getBalance(partyAAddress);
  const balBAfterA = await new ethers.JsonRpcProvider(chainA.rpcUrl).getBalance(partyBAddress);

  console.error("--- Verifying Chain A payouts match Chain B's attested state ---");
  await assertEqual("partyA payout on Chain A", balAAfterA - balABeforeA, stateB.balanceA);
  await assertEqual("partyB payout on Chain A (net of its own withdraw() gas)", balBAfterA - balBBeforeA + gasCostA, stateB.balanceB);

  console.error("\nChain B -> Chain A settle succeeded: Chain B's channel state (0.9/1.1 ETH), reached via a real");
  console.error("consensus_proof.circom proof + Chain A's OWN LightClientVerifier, produced an identical payout on");
  console.error("Chain A — the exact same mechanism as Part 1, running in the opposite direction. Bidirectional");
  console.error("relay confirmed: this is not just relayChannelState()'s fromChain/toChain params being flexible,");
  console.error("both chains genuinely have their own independent LightClientVerifier deployment.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
