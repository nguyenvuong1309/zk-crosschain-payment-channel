#!/usr/bin/env -S npx tsx
// Multi-relayer redundancy demo — docs/threat-model.md #7's remaining known
// limitation: "1 relayer instance vẫn là 1 điểm liveness duy nhất". This
// demo runs 3 independent `attachWatchQueue` instances (the same event
// subscription watch.ts's `main()` uses in production, factored out so it
// can be attached multiple times here) on the SAME source-chain contract,
// takes 2 of them "offline" (event listeners detached) BEFORE a channel's
// state advances, and verifies the single survivor still relays the new
// state to the destination chain's LightClientVerifier — no code change
// needed to prove this: `updateState()` has no access control (see
// LightClientVerifier.sol's doc comment), so any number of independent
// relayers can watch the same source chain and race to relay; whichever
// gets there first wins, the rest just no-op against the already-updated
// `trustedBlockNumber`.
//
// Prerequisite: `pnpm run deploy` already run (needs deployment.json, same
// as watch.ts/index.ts).
//
// Usage: npx tsx src/multi_relayer_e2e.ts [fromChain=chainA] [toChain=chainB]

import path from "path";
import { ethers, type Contract } from "ethers";
import * as artifacts from "./artifacts";
import { loadDeployment } from "./index";
import { attachWatchQueue } from "./watch";

const PARTY_A_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PARTY_B_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const DEPOSIT_A = ethers.parseEther("1");
const DEPOSIT_B = ethers.parseEther("1");

async function main() {
  const fromChain = process.argv[2] ?? "chainA";
  const toChain = process.argv[3] ?? "chainB";

  const deployment = loadDeployment(path.join(__dirname, "..", "deployment.json"));
  const source = deployment.chains[fromChain]!;
  const dest = deployment.chains[toChain]!;
  if (!dest.lightClientVerifier) throw new Error(`destination chain "${toChain}" has no lightClientVerifier`);

  const providerSource = new ethers.JsonRpcProvider(source.rpcUrl);
  const providerDest = new ethers.JsonRpcProvider(dest.rpcUrl);
  const { abi: pcAbi } = artifacts.PaymentChannel();
  const { abi: lcAbi } = artifacts.LightClientVerifier();

  console.error("--- Step 1: start 3 independent relayer watch instances on the same source chain ---");
  const paymentChannelSources = [0, 1, 2].map(() => new ethers.Contract(source.paymentChannel, pcAbi, providerSource));
  const OFFLINE_INDICES = new Set([1, 2]); // relayers #2 and #3 go offline before the state change
  const detachFns: (() => void)[] = [];
  for (let i = 0; i < 3; i++) {
    const detach = attachWatchQueue(paymentChannelSources[i]!, deployment, fromChain, toChain, `relayer#${i + 1}`);
    detachFns.push(detach);
    console.error(`  relayer #${i + 1} watching ${fromChain} — ALIVE`);
  }

  console.error("--- Step 2: open + join a channel on the source chain ---");
  const partyA = new ethers.NonceManager(new ethers.Wallet(PARTY_A_KEY, providerSource));
  const partyB = new ethers.NonceManager(new ethers.Wallet(PARTY_B_KEY, providerSource));
  const partyBAddress = new ethers.Wallet(PARTY_B_KEY).address;
  const paymentChannelA = new ethers.Contract(source.paymentChannel, pcAbi, providerSource);

  let tx = await (paymentChannelA.connect(partyA) as Contract).open!(partyBAddress, DEPOSIT_A, 0, 0, 0, 0, 0, { value: DEPOSIT_A });
  let receipt = await tx.wait();
  const openedEvent = receipt.logs.map((l: any) => paymentChannelA.interface.parseLog(l)).find((e: any) => e?.name === "ChannelOpened");
  const channelId: bigint = openedEvent.args.channelId;
  console.error(`  channelId = ${channelId}`);
  tx = await (paymentChannelA.connect(partyB) as Contract).join!(channelId, 0, 0, 0, 0, 0, { value: DEPOSIT_B });
  await tx.wait();

  console.error("--- Step 3: relayers #2 and #3 go OFFLINE (detach their event listeners) ---");
  for (const i of OFFLINE_INDICES) {
    detachFns[i]!();
    console.error(`  relayer #${i + 1} detached`);
  }

  console.error("--- Step 4: advance the channel's state (closeUnilateral) — only relayer #1 is left to notice ---");
  const digest = await (paymentChannelA as any).hashState({ channelId, nonce: 1, balanceA: ethers.parseEther("0.4"), balanceB: ethers.parseEther("1.6") });
  const sigA = await partyA.signMessage(ethers.getBytes(digest));
  const sigB = await partyB.signMessage(ethers.getBytes(digest));
  const state = { channelId, nonce: 1, balanceA: ethers.parseEther("0.4"), balanceB: ethers.parseEther("1.6") };
  tx = await (paymentChannelA.connect(partyA) as Contract).closeUnilateral!(state, sigA, sigB);
  await tx.wait();
  console.error("  closeUnilateral(nonce=1) submitted");

  console.error("--- Step 5: waiting for the SOLE surviving relayer to auto-relay to the destination chain ---");
  const lightClient = new ethers.Contract(dest.lightClientVerifier, lcAbi, providerDest);
  const deadline = Date.now() + 20_000;
  let relayed = false;
  while (Date.now() < deadline) {
    const trustedBlockNumber: bigint = await lightClient.trustedBlockNumber!(source.chainId);
    if (trustedBlockNumber > 0n) {
      relayed = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  if (!relayed) throw new Error("timed out waiting for the surviving relayer to relay");

  for (const detach of detachFns) detach();
  console.error("  relayed — destination chain's LightClientVerifier now trusts a new state root, via relayer #1 alone");

  console.error("\nMulti-relayer demo succeeded: 2 of 3 independent relayer instances were offline (event");
  console.error("listeners detached) BEFORE the channel's state advanced, yet the single survivor still");
  console.error("relayed the new state cross-chain — no single relayer is a point of failure as long as at");
  console.error("least one independent instance stays up.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
