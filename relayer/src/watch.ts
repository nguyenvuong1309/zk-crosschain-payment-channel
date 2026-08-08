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
import { readConfirmed } from "./rpcSync";

// Events that mean "this channel's on-chain state on fromChain just
// advanced, relay it" — mirrors watchtower/src/monitor.ts's event set plus
// the cooperative-close path (watchtower doesn't need that one: a
// cooperative close is already final/uncontestable, but a cross-chain
// relay still needs to know about it).
const RELEVANT_EVENTS = ["ChannelClosedCooperatively", "ChannelClosedUnilaterally", "ChannelChallenged"] as const;

interface QueueItem {
  channelId: string;
  reason: string;
  // The event's own block number — used to confirm the RPC has actually
  // caught up before reading channels() state below (see rpcSync.ts's
  // header comment: a real read-staleness race found testing against a
  // forked/real RPC, reads right after a state change can return old
  // data).
  eventBlockNumber: number;
}

/// Serializes ALL relays through one queue rather than firing them
/// concurrently — relayChannelState() sends from a plain ethers.Wallet (not
/// a NonceManager), and this codebase has repeatedly hit stale-nonce races
/// from concurrent sends off the same wallet against Anvil (see
/// deploy.ts/e2e_demo.ts's NonceManager comments) — serializing sidesteps
/// that class of bug entirely instead of re-solving it here.
export class RelayQueue {
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

  private async relayOne({ channelId, reason, eventBlockNumber }: QueueItem): Promise<void> {
    try {
      const provider = this.paymentChannelSource.runner!.provider!;
      const ch = await readConfirmed(provider, eventBlockNumber, () => this.paymentChannelSource.getChannel!(channelId));
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

/// Subscribes a RelayQueue to `paymentChannelSource`'s relevant events —
/// the reusable half of `main()` below, factored out so
/// `multi_relayer_e2e.ts` can attach several independent watch instances
/// to the same source contract (each with its own queue/label) without
/// duplicating this wiring. Returns a function to detach (simulating that
/// instance going offline).
export function attachWatchQueue(
  paymentChannelSource: ethers.Contract,
  deployment: Deployment,
  fromChain: string,
  toChain: string,
  label = "watch"
): () => void {
  const queue = new RelayQueue(deployment, fromChain, toChain, paymentChannelSource);
  const handlers = RELEVANT_EVENTS.map((eventName) => {
    // ethers v6 passes the triggering EventLog as the LAST argument
    // regardless of how many params the event itself declares — used here
    // purely for `.log.blockNumber` (see QueueItem's eventBlockNumber doc
    // comment above).
    const handler = (channelId: bigint, ...rest: unknown[]) => {
      const eventPayload = rest[rest.length - 1] as { log?: { blockNumber?: number } } | undefined;
      const eventBlockNumber = eventPayload?.log?.blockNumber ?? 0;
      console.error(`[${label}] channel ${channelId}: event ${eventName} at block ${eventBlockNumber}`);
      queue.push({ channelId: channelId.toString(), reason: eventName, eventBlockNumber });
    };
    paymentChannelSource.on(eventName, handler);
    return { eventName, handler };
  });

  return () => {
    for (const { eventName, handler } of handlers) paymentChannelSource.off(eventName, handler);
  };
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

  const detach = attachWatchQueue(paymentChannelSource, deployment, fromChain, toChain);

  console.error(`[watch] watching ${source.paymentChannel} on ${fromChain} (${source.rpcUrl}), relaying to ${toChain} on new state`);
  console.error(`[watch] events: ${RELEVANT_EVENTS.join(", ")}`);

  // Keep the process alive — event listeners above are what actually do
  // the work. SIGINT/SIGTERM (Ctrl-C, `docker stop`, etc.) exit cleanly
  // instead of leaving a dangling WebSocket/polling provider.
  const shutdown = () => {
    console.error("\n[watch] shutting down");
    detach();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// Guard, like every other entry-point script in this repo (index.ts,
// deploy.ts) — without it, importing this module just for
// `attachWatchQueue`/`RelayQueue` (e.g. multi_relayer_e2e.ts) would ALSO
// run this file's own `main()` as an unwanted side effect, racing a SECOND
// independent relay against whatever imported it. Exactly the bug that
// caused a `replacement transaction underpriced` collision when this guard
// was missing — see docs/threat-model.md.
if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
