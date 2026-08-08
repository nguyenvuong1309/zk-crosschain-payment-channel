#!/usr/bin/env -S npx tsx
// Multi-watchtower redundancy demo — docs/threat-model.md giả định #2's
// remaining known limitation: "1 watchtower là 1 điểm liveness duy nhất —
// production nên chạy nhiều watchtower độc lập". This demo actually runs
// 3 (real HTTP servers + real event listeners, not mocked), simulates 2 of
// them being OFFLINE when partyA cheats, and verifies the single surviving
// watchtower still rescues the channel — no code change needed to prove
// this, the architecture already supports it (challenge() isn't
// `onlyParty`, so any number of independent watchtowers can race to
// protect the same channel; first valid challenge wins, the rest just no-op
// against the already-updated state).
//
// Also the FIRST demo in this repo to exercise the REAL HTTP checkpoint API
// (server.ts's `POST /checkpoint`) and the REAL event-listener path
// (monitor.ts's `startMonitoring`) end to end — every earlier e2e demo
// called `submitCheckpoint`/`reactToChannel` directly as plain function
// calls, bypassing both. Three separate watchtower "instances" here are
// each a real `http.Server` on its own port with its own `CheckpointStore`
// and own wallet — not simulated, genuinely independent processes' worth
// of state, just co-located in one Node process for demo convenience (no
// Docker/separate-OS-process dependency needed to prove the same property).
//
// Usage: npx tsx src/multi_watchtower_e2e.ts

import path from "path";
import { ethers, type Contract, type Signer } from "ethers";
import * as artifacts from "./artifacts";
import { CheckpointStore } from "./store";
import { createServer } from "./server";
import { startMonitoring, type OnAction } from "./monitor";
import { readConfirmed } from "./rpcSync";

const RPC_URL = process.env.WATCHTOWER_RPC_URL ?? "http://127.0.0.1:8545";

// Anvil's well-known default accounts #0-#4 — local demo only.
const PARTY_A_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const PARTY_B_KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const WATCHTOWER_KEYS = [
  "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a", // #2
  "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6", // #3
  "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a", // #4
];
const WATCHTOWER_PORTS = [8801, 8802, 8803];
const OFFLINE_INDICES = new Set([1, 2]); // watchtowers #2 and #3 (0-indexed 1,2) are "offline" — only #1 stays up

const DEPOSIT_A = ethers.parseEther("1");
const DEPOSIT_B = ethers.parseEther("1");

async function signState(wallet: Signer, paymentChannel: Contract, state: { channelId: bigint; nonce: number; balanceA: bigint; balanceB: bigint }) {
  const digest: string = await paymentChannel.hashState!(state);
  return wallet.signMessage(ethers.getBytes(digest));
}

async function postCheckpoint(port: number, body: Record<string, string>): Promise<{ stored: boolean; reason?: string }> {
  const res = await fetch(`http://127.0.0.1:${port}/checkpoint`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return (await res.json()) as { stored: boolean; reason?: string };
}

async function assertEqual(label: string, actual: bigint, expected: bigint): Promise<void> {
  if (actual.toString() !== expected.toString()) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
  console.error(`  OK  ${label} = ${actual}`);
}

async function main() {
  const provider = new ethers.JsonRpcProvider(RPC_URL);
  provider.pollingInterval = 300;

  const partyAWallet = new ethers.NonceManager(new ethers.Wallet(PARTY_A_KEY, provider));
  const partyBWallet = new ethers.NonceManager(new ethers.Wallet(PARTY_B_KEY, provider));
  const partyAAddress = new ethers.Wallet(PARTY_A_KEY).address;
  const partyBAddress = new ethers.Wallet(PARTY_B_KEY).address;

  console.error("--- Step 0: deploy PaymentChannel ---");
  const { abi: verifierAbi, bytecode: verifierBytecode } = artifacts.Groth16Verifier();
  const { abi: pcAbi, bytecode: pcBytecode } = artifacts.PaymentChannel();
  const verifier = await (await new ethers.ContractFactory(verifierAbi, verifierBytecode, partyAWallet).deploy()).waitForDeployment();
  const paymentChannel = (await (
    await new ethers.ContractFactory(pcAbi, pcBytecode, partyAWallet).deploy(await verifier.getAddress(), ethers.ZeroAddress)
  ).waitForDeployment()) as Contract;
  const paymentChannelAddress = await paymentChannel.getAddress();
  console.error(`  PaymentChannel deployed at ${paymentChannelAddress}`);

  console.error("--- Step 1: start 3 independent watchtower instances (real HTTP servers + real event listeners) ---");
  const stopFns: (() => void)[] = [];
  const servers: import("http").Server[] = [];
  for (let i = 0; i < 3; i++) {
    const wallet = new ethers.NonceManager(new ethers.Wallet(WATCHTOWER_KEYS[i]!, provider));
    const store = new CheckpointStore(path.join(__dirname, "..", `checkpoints.multi-demo-${i}.json`));
    const readOnlyChannel = new ethers.Contract(paymentChannelAddress, pcAbi, provider);
    const onAction: OnAction = (info) => console.error(`  [watchtower #${i + 1}] channel ${info.channelId}: ${info.action}${info.reason ? ` (${info.reason})` : ""}`);

    const server = createServer({ paymentChannel: readOnlyChannel, store });
    server.listen(WATCHTOWER_PORTS[i]);
    servers.push(server);

    if (OFFLINE_INDICES.has(i)) {
      // "Offline" = never subscribes to events at all — the checkpoint API
      // being briefly reachable at startup (to receive a checkpoint before
      // going dark, exactly like a real instance that later crashes) is
      // realistic; NOT monitoring is what actually matters for this demo.
      console.error(`  watchtower #${i + 1} on :${WATCHTOWER_PORTS[i]} — will go OFFLINE (no event monitoring) before the cheat attempt`);
    } else {
      const stop = startMonitoring({ paymentChannel: readOnlyChannel, wallet: wallet as unknown as ethers.Wallet, store, onAction });
      stopFns.push(stop);
      console.error(`  watchtower #${i + 1} on :${WATCHTOWER_PORTS[i]} — ALIVE, monitoring events`);
    }
  }

  console.error("--- Step 2: open + join a channel ---");
  let tx = await (paymentChannel.connect(partyAWallet) as Contract).open!(partyBAddress, DEPOSIT_A, 0, 0, 0, 0, 0, { value: DEPOSIT_A });
  let receipt = await tx.wait();
  const openedEvent = receipt.logs.map((l: any) => paymentChannel.interface.parseLog(l)).find((e: any) => e?.name === "ChannelOpened");
  const channelId: bigint = openedEvent.args.channelId;
  console.error(`  channelId = ${channelId}`);
  tx = await (paymentChannel.connect(partyBWallet) as Contract).join!(channelId, 0, 0, 0, 0, 0, { value: DEPOSIT_B });
  await tx.wait();

  console.error("--- Step 3: 2 off-chain rounds, checkpointed via REAL HTTP POST to ALL 3 watchtowers ---");
  const round1 = { channelId, nonce: 1, balanceA: ethers.parseEther("0.7"), balanceB: ethers.parseEther("1.3") };
  const round1SigA = await signState(partyAWallet, paymentChannel, round1);
  const round1SigB = await signState(partyBWallet, paymentChannel, round1);
  const round2 = { channelId, nonce: 2, balanceA: ethers.parseEther("0.2"), balanceB: ethers.parseEther("1.8") };
  const round2SigA = await signState(partyAWallet, paymentChannel, round2);
  const round2SigB = await signState(partyBWallet, paymentChannel, round2);

  for (const [round, sigA, sigB] of [
    [round1, round1SigA, round1SigB],
    [round2, round2SigA, round2SigB],
  ] as const) {
    for (const port of WATCHTOWER_PORTS) {
      const result = await postCheckpoint(port, {
        channelId: round.channelId.toString(),
        nonce: round.nonce.toString(),
        balanceA: round.balanceA.toString(),
        balanceB: round.balanceB.toString(),
        sigA,
        sigB,
      });
      if (!result.stored) throw new Error(`checkpoint POST to :${port} was not stored: ${result.reason}`);
    }
  }
  console.error("  round 1 + round 2 checkpointed via HTTP to all 3 watchtowers");

  console.error("--- Step 4: watchtowers #2 and #3 go OFFLINE (stop their HTTP servers entirely) ---");
  for (const i of OFFLINE_INDICES) {
    servers[i]!.close();
    console.error(`  watchtower #${i + 1} shut down`);
  }

  console.error("--- Step 5: partyB goes silent. partyA cheats: closes with the STALE round-1 state ---");
  tx = await (paymentChannel.connect(partyAWallet) as Contract).closeUnilateral!(round1, round1SigA, round1SigB);
  await tx.wait();
  console.error("  closeUnilateral(nonce=1) submitted — only watchtower #1 is left to notice");

  console.error("--- Step 6: waiting for the SOLE surviving watchtower's event listener to react ---");
  const deadline = Date.now() + 15_000;
  let rescued = false;
  while (Date.now() < deadline) {
    const ch = await paymentChannel.getChannel!(channelId);
    if (ch.nonce === 2n) {
      rescued = true;
      break;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  if (!rescued) throw new Error("timed out waiting for the surviving watchtower to rescue the channel");
  console.error("  rescued — on-chain nonce is now 2 (the true latest state), via watchtower #1 alone");

  for (const stop of stopFns) stop();
  for (const server of servers) server.close();

  console.error("--- Step 7: wait out the challenge window and withdraw ---");
  await provider.send("evm_increaseTime", [24 * 60 * 60 + 1]);
  await provider.send("evm_mine", []);

  const balABefore = await readConfirmed(provider, await provider.getBlockNumber(), () => provider.getBalance(partyAAddress));
  const balBBefore = await readConfirmed(provider, await provider.getBlockNumber(), () => provider.getBalance(partyBAddress));

  tx = await (paymentChannel.connect(partyBWallet) as Contract).withdraw!(channelId);
  const withdrawReceipt = await tx.wait();

  const balAAfter = await readConfirmed(provider, withdrawReceipt.blockNumber, () => provider.getBalance(partyAAddress));
  const balBAfter = await readConfirmed(provider, withdrawReceipt.blockNumber, () => provider.getBalance(partyBAddress));
  const gasCost: bigint = BigInt(withdrawReceipt.gasUsed) * BigInt(withdrawReceipt.gasPrice);

  console.error("--- Verifying payout matches the RESCUED state despite 2/3 watchtowers being offline ---");
  await assertEqual("partyA payout", balAAfter - balABefore, round2.balanceA);
  await assertEqual("partyB payout (net of its own withdraw() gas)", balBAfter - balBBefore + gasCost, round2.balanceB);

  console.error("\nMulti-watchtower demo succeeded: 2 of 3 independent watchtower instances went offline");
  console.error("(HTTP servers stopped, event listeners never attached) BEFORE partyA's cheat attempt, yet the");
  console.error("single survivor still rescued the channel — no single watchtower is a point of failure as long");
  console.error("as at least one independent instance stays up and had the checkpoint.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
