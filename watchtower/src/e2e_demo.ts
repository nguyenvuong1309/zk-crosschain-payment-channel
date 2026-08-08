#!/usr/bin/env -S npx tsx
// End-to-end watchtower demo: deploys a PaymentChannel on a local Anvil
// chain, has partyA and partyB agree on TWO off-chain states, checkpoints
// BOTH with the watchtower (as a real client would after every signed
// update), then has partyA cheat by unilaterally closing with the OLDER
// (nonce=1) state while partyB is completely silent/offline for the rest of
// the script. The watchtower — with no help from partyB — detects the stale
// close from its event listener and automatically submits the correct
// newer (nonce=2) state via challenge(), protecting partyB's larger share.
//
// Prerequisites: an Anvil chain running on 127.0.0.1:8545 (plain `anvil`,
// or chains/start_chain_a.sh) and `forge build` already run in contracts/.
//
// Usage: npx tsx src/e2e_demo.ts

import path from "path";
import { ethers, type Contract, type Signer } from "ethers";
import * as artifacts from "./artifacts";
import { CheckpointStore } from "./store";
import { submitCheckpoint, type ChannelStateInput } from "./checkpoint";
import { reactToChannel } from "./monitor";
import { readConfirmed } from "./rpcSync";

const RPC_URL = process.env.WATCHTOWER_RPC_URL ?? "http://127.0.0.1:8545";

// Anvil's well-known default accounts #0/#1/#2 — local demo only.
const PARTY_A_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PARTY_B_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const WATCHTOWER_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

const DEPOSIT_A = ethers.parseEther("1");
const DEPOSIT_B = ethers.parseEther("1");

async function signState(wallet: Signer, paymentChannel: Contract, state: ChannelStateInput): Promise<string> {
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
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  provider.pollingInterval = 300; // fast enough to see the demo react promptly

  // Wrapped in NonceManager: ethers v6's default "pending"-tag nonce lookup
  // can return a stale value if queried again immediately after a prior send
  // on the same provider instance (observed against Anvil in this repo —
  // NonceManager tracks the next nonce in-memory instead of re-querying).
  // One instance per address — partyA and "the deployer" are the SAME
  // account here, so they must share one NonceManager, not two independent
  // in-memory counters for the same underlying nonce.
  const partyAWallet = new ethers.NonceManager(new ethers.Wallet(PARTY_A_KEY, provider));
  const deployerWallet = partyAWallet;
  const partyBWallet = new ethers.NonceManager(new ethers.Wallet(PARTY_B_KEY, provider));
  const watchtowerWallet = new ethers.NonceManager(new ethers.Wallet(WATCHTOWER_KEY, provider));
  // NonceManager doesn't expose a sync `.address` — use plain (unconnected)
  // wallets just for address lookups.
  const partyAAddress = new ethers.Wallet(PARTY_A_KEY).address;
  const partyBAddress = new ethers.Wallet(PARTY_B_KEY).address;

  console.error("--- Step 0: deploy PaymentChannel ---");
  const { abi: verifierAbi, bytecode: verifierBytecode } = artifacts.Groth16Verifier();
  const { abi: pcAbi, bytecode: pcBytecode } = artifacts.PaymentChannel();

  const verifierFactory = new ethers.ContractFactory(verifierAbi, verifierBytecode, deployerWallet);
  const verifier = await (await verifierFactory.deploy()).waitForDeployment();

  const pcFactory = new ethers.ContractFactory(pcAbi, pcBytecode, deployerWallet);
  const paymentChannel = (await (await pcFactory.deploy(await verifier.getAddress(), ethers.ZeroAddress)).waitForDeployment()) as Contract;
  console.error(`  PaymentChannel deployed at ${await paymentChannel.getAddress()}`);

  const store = new CheckpointStore(path.join(__dirname, "..", "checkpoints.demo.json"));
  const onAction = (info: { channelId: unknown; action: string; reason?: string }) =>
    console.error(`  [watchtower] channel ${info.channelId}: ${info.action}${info.reason ? ` (${info.reason})` : ""}`);

  console.error("--- Step 1: open + join a channel ---");
  let tx = await (paymentChannel.connect(partyAWallet) as Contract).open!(partyBAddress, DEPOSIT_A, 0, 0, 0, 0, 0, { value: DEPOSIT_A });
  let receipt = await tx.wait();
  const openedEvent = receipt.logs.map((l: any) => paymentChannel.interface.parseLog(l)).find((e: any) => e && e.name === "ChannelOpened");
  const channelId: bigint = openedEvent.args.channelId;
  console.error(`  channelId = ${channelId}`);

  tx = await (paymentChannel.connect(partyBWallet) as Contract).join!(channelId, 0, 0, 0, 0, 0, { value: DEPOSIT_B });
  await tx.wait();

  console.error("--- Step 2: two off-chain rounds, BOTH checkpointed with the watchtower ---");
  const round1: ChannelStateInput = { channelId, nonce: 1, balanceA: ethers.parseEther("0.7"), balanceB: ethers.parseEther("1.3") };
  const round1SigA = await signState(partyAWallet, paymentChannel, round1);
  const round1SigB = await signState(partyBWallet, paymentChannel, round1);
  await submitCheckpoint({ paymentChannel, store, state: round1 }, round1SigA, round1SigB);
  console.error("  round 1 (nonce=1, 0.7/1.3) checkpointed");

  const round2: ChannelStateInput = { channelId, nonce: 2, balanceA: ethers.parseEther("0.2"), balanceB: ethers.parseEther("1.8") };
  const round2SigA = await signState(partyAWallet, paymentChannel, round2);
  const round2SigB = await signState(partyBWallet, paymentChannel, round2);
  await submitCheckpoint({ paymentChannel, store, state: round2 }, round2SigA, round2SigB);
  console.error("  round 2 (nonce=2, 0.2/1.8) checkpointed — this is the TRUE latest state");

  console.error("--- Step 3: partyB goes offline. partyA cheats: closes with the STALE round-1 state ---");
  tx = await (paymentChannel.connect(partyAWallet) as Contract).closeUnilateral!(round1, round1SigA, round1SigB);
  const closeReceipt = await tx.wait();
  console.error(`  closeUnilateral(nonce=1) submitted, tx ${closeReceipt.hash} — partyB never sees this, never responds`);

  console.error("--- Step 4: watchtower reacts (no help from partyB) ---");
  // In production this fires from the event listener (see monitor.ts
  // startMonitoring) within one polling interval; called directly here so
  // the demo doesn't need to sleep an arbitrary amount waiting for it.
  // minBlockNumber = closeReceipt's own block — see monitor.ts's
  // reactToChannel doc comment / rpcSync.ts for why this matters (a real
  // race observed against a forked/real RPC, reproduced and diagnosed via
  // this exact demo — see docs/threat-model.md).
  const challengeReceipt = await reactToChannel({
    paymentChannel,
    wallet: watchtowerWallet as unknown as ethers.Wallet,
    store,
    channelId,
    minBlockNumber: closeReceipt.blockNumber,
    onAction,
  });

  // Confirm against the CHALLENGE tx's own block (not closeReceipt's,
  // which is from before the rescue) — same reasoning as above.
  const chAfterChallenge = await readConfirmed(provider, challengeReceipt!.blockNumber, () => paymentChannel.channels!(channelId));
  await assertEqual("on-chain nonce after watchtower's rescue challenge", chAfterChallenge.nonce, 2n);
  await assertEqual("on-chain balanceA after rescue", chAfterChallenge.balanceA, round2.balanceA as bigint);
  await assertEqual("on-chain balanceB after rescue", chAfterChallenge.balanceB, round2.balanceB as bigint);

  console.error("--- Step 5: wait out the challenge window and withdraw ---");
  await provider.send("evm_increaseTime", [24 * 60 * 60 + 1]);
  await provider.send("evm_mine", []);

  // Fresh provider instances for these balance snapshots — reusing `provider`
  // for rapid sequential eth_getBalance calls was observed to return stale
  // values against Anvil (same class of issue as the nonce staleness noted
  // above for NonceManager). Fresh instances alone turned out NOT to be
  // enough against a forked/real RPC though (see rpcSync.ts's header
  // comment) — readConfirmed's block-number + stability-retry check is the
  // actual fix; kept as a fresh provider on top for defense in depth.
  const beforeProvider = new ethers.JsonRpcProvider(RPC_URL);
  const beforeBlock = await beforeProvider.getBlockNumber();
  const balABefore = await readConfirmed(beforeProvider, beforeBlock, () => beforeProvider.getBalance(partyAAddress));
  const balBBefore = await readConfirmed(beforeProvider, beforeBlock, () => beforeProvider.getBalance(partyBAddress));

  // partyB is "offline" so a neutral relayer... but withdraw() is
  // onlyParty; use partyA (the cheat attempt failed, but partyA still gets
  // their honest share back — this call doesn't require B).
  tx = await (paymentChannel.connect(partyAWallet) as Contract).withdraw!(channelId);
  const withdrawReceipt = await tx.wait();
  const gasCost: bigint = BigInt(withdrawReceipt.gasUsed) * BigInt(withdrawReceipt.gasPrice);

  const afterProvider = new ethers.JsonRpcProvider(RPC_URL);
  const balAAfter = await readConfirmed(afterProvider, withdrawReceipt.blockNumber, () => afterProvider.getBalance(partyAAddress));
  const balBAfter = await readConfirmed(afterProvider, withdrawReceipt.blockNumber, () => afterProvider.getBalance(partyBAddress));

  console.error("--- Verifying final payout matches the RESCUED state, not the fraudulent one ---");
  await assertEqual("partyA payout (net of its own withdraw() gas)", balAAfter - balABefore + gasCost, round2.balanceA as bigint);
  await assertEqual("partyB payout (received while completely offline)", balBAfter - balBBefore, round2.balanceB as bigint);

  console.error("\nWatchtower demo succeeded: partyA's stale closeUnilateral(nonce=1, 0.7/1.3) was overridden");
  console.error("by the watchtower's automatic challenge(nonce=2, 0.2/1.8) — partyB got the correct 1.8 ETH");
  console.error("payout despite never once going online during the entire dispute.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
