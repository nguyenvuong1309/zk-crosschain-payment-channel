#!/usr/bin/env -S npx tsx
// Relayer watch-loop — Milestone 4 hardening of the Milestone 3 relayer
// (docs/threat-model.md #7 notes the one-shot `index.ts` relayer as a known
// gap: "CHƯA có watch-loop tự động theo dõi Chain A liên tục"). This is
// that watch-loop: it subscribes to the events that mean a channel's state
// on `fromChain` just advanced, and relays the new state to `toChain`
// automatically — no operator running `index.ts` by hand after every
// off-chain update.
//
// This only affects LIVENESS, same as the one-shot relayer (see index.ts's
// header comment and docs/threat-model.md #7) — a crashed/malicious watcher
// delays settlement, it can never forge a proof or attest to a state that
// wasn't actually reached on `fromChain`.
//
// Usage: npx tsx src/watch.ts [fromChain=chainA] [toChain=chainB]
//   DEPLOYMENT_FILE (env) overrides the default ../deployment.json, same as index.ts.

import "dotenv/config";
import path from "path";
import { ethers } from "ethers";
import * as artifacts from "./artifacts";
import { relayChannelState, loadDeployment } from "./index";
import type { Deployment } from "./deploy";

// Events that mean "this channel's on-chain state on fromChain just
// advanced, relay it" — mirrors watchtower/src/monitor.ts's event set plus
// the cooperative-close path (watchtower doesn't need that one: a
// cooperative close is already final/uncontestable, but a cross-chain
// relay still needs to know about it).
const RELEVANT_EVENTS = ["ChannelClosedCooperatively", "ChannelClosedUnilaterally", "ChannelChallenged"] as const;

interface QueueItem {
  channelId: string;
  reason: string;
}

/// Serializes ALL relays through one queue rather than firing them
/// concurrently — relayChannelState() sends from a plain ethers.Wallet (not
/// a NonceManager), and this codebase has repeatedly hit stale-nonce races
/// from concurrent sends off the same wallet against Anvil (see
/// deploy.ts/e2e_demo.ts's NonceManager comments) — serializing sidesteps
/// that class of bug entirely instead of re-solving it here.
class RelayQueue {
  private queue: QueueItem[] = [];
  private draining = false;
  // channelId -> last nonce successfully relayed, so a burst of events for
  // the same already-relayed state (e.g. ChannelChallenged firing right
  // after ChannelClosedUnilaterally settles down) doesn't waste gas
  // re-submitting an unchanged stateRoot.
  private lastRelayedNonce = new Map<string, bigint>();

  constructor(
    private deployment: Deployment,
    private fromChain: string,
    private toChain: string,
    private paymentChannelSource: ethers.Contract
  ) {}

  push(item: QueueItem): void {
    this.queue.push(item);
    void this.drain();
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      while (this.queue.length > 0) {
        const item = this.queue.shift()!;
        await this.relayOne(item);
      }
    } finally {
      this.draining = false;
    }
  }

  private async relayOne({ channelId, reason }: QueueItem): Promise<void> {
    try {
      const ch = await this.paymentChannelSource.channels!(channelId);
      const currentNonce: bigint = ch.nonce;
      const last = this.lastRelayedNonce.get(channelId);
      if (last !== undefined && last >= currentNonce) {
        console.error(`[watch] channel ${channelId}: skip (${reason}) — already relayed nonce ${last} >= on-chain ${currentNonce}`);
        return;
      }

      console.error(`[watch] channel ${channelId}: relaying (${reason}), on-chain nonce=${currentNonce}`);
      const result = await relayChannelState({
        deployment: this.deployment,
        channelId,
        fromChain: this.fromChain,
        toChain: this.toChain,
      });
      this.lastRelayedNonce.set(channelId, result.nonce);
      console.error(`[watch] channel ${channelId}: relayed, tx ${result.txHash}`);
    } catch (err) {
      // Never let one bad relay kill the daemon — log and keep watching.
      // A failed relay is a liveness hiccup (see header comment), not a
      // safety issue; the next qualifying event retries it.
      console.error(`[watch] channel ${channelId}: relay FAILED (${reason}):`, err instanceof Error ? err.message : err);
    }
  }
}

async function main() {
  const fromChain = process.argv[2] ?? "chainA";
  const toChain = process.argv[3] ?? "chainB";

  const deploymentPath = process.env.DEPLOYMENT_FILE ?? path.join(__dirname, "..", "deployment.json");
  const deployment = loadDeployment(deploymentPath);

  const source = deployment.chains[fromChain];
  const dest = deployment.chains[toChain];
  if (!source) throw new Error(`unknown source chain "${fromChain}" — not in deployment.json's chains`);
  if (!dest?.lightClientVerifier) {
    throw new Error(`destination chain "${toChain}" has no lightClientVerifier — redeploy it with "lightClient": true in chains.config.json`);
  }

  const providerSource = new ethers.JsonRpcProvider(source.rpcUrl);
  const { abi } = artifacts.PaymentChannel();
  const paymentChannelSource = new ethers.Contract(source.paymentChannel, abi, providerSource);

  const queue = new RelayQueue(deployment, fromChain, toChain, paymentChannelSource);

  for (const eventName of RELEVANT_EVENTS) {
    paymentChannelSource.on(eventName, (channelId: bigint) => {
      queue.push({ channelId: channelId.toString(), reason: eventName });
    });
  }

  console.error(`[watch] watching ${source.paymentChannel} on ${fromChain} (${source.rpcUrl}), relaying to ${toChain} on new state`);
  console.error(`[watch] events: ${RELEVANT_EVENTS.join(", ")}`);

  // Keep the process alive — event listeners above are what actually do
  // the work. SIGINT/SIGTERM (Ctrl-C, `docker stop`, etc.) exit cleanly
  // instead of leaving a dangling WebSocket/polling provider.
  const shutdown = () => {
    console.error("\n[watch] shutting down");
    paymentChannelSource.removeAllListeners();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
