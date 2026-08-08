// Verifies and accepts a checkpoint: a copy of a mutually co-signed
// ChannelState a party (or their client/wallet) sends the watchtower right
// after signing it off-chain, so the watchtower has something to defend
// with if that party later goes offline during a dispute window.
//
// The watchtower does NOT trust whatever it's sent — every checkpoint is
// independently verified against the channel's actual on-chain
// partyA/partyB addresses and hashState() domain separator before being
// stored. A malicious submitter gains nothing by sending a fake/unsigned
// state: it simply gets rejected.

import { ethers, type Contract } from "ethers";
import type { CheckpointStore, Checkpoint } from "./store";

export class InvalidCheckpointError extends Error {}

export interface ChannelStateInput {
  channelId: string | bigint | number;
  nonce: string | bigint | number;
  balanceA: string | bigint | number;
  balanceB: string | bigint | number;
}

/// @param opts.paymentChannel ethers.Contract (read-only is fine) for the
///                            PaymentChannel this checkpoint is for
/// @param opts.state          { channelId, nonce, balanceA, balanceB }
/// @param opts.sigA/sigB      hex signature strings
export async function verifyCheckpoint({
  paymentChannel,
  state,
  sigA,
  sigB,
}: {
  paymentChannel: Contract;
  state: ChannelStateInput;
  sigA: string;
  sigB: string;
}): Promise<{ checkpoint: Checkpoint; digest: string }> {
  const ch = await paymentChannel.getChannel!(state.channelId);
  if (ch.partyA === ethers.ZeroAddress) {
    throw new InvalidCheckpointError(`channel ${state.channelId} does not exist`);
  }

  // Mirrors PaymentChannel.sol::_verifyBothSignatures exactly — same digest
  // (hashState, domain-separated), same personal-sign recovery. Returned to
  // the caller so submitCheckpoint() can reuse it for the on-chain
  // commitCheckpoint() watermark instead of re-deriving it via a second RPC
  // call for the identical `state` (a real /code-review finding).
  const digest: string = await paymentChannel.hashState!(state);
  const recoveredA = ethers.verifyMessage(ethers.getBytes(digest), sigA);
  const recoveredB = ethers.verifyMessage(ethers.getBytes(digest), sigB);

  if (recoveredA !== ch.partyA) {
    throw new InvalidCheckpointError(`sigA does not recover to this channel's partyA (got ${recoveredA}, expected ${ch.partyA})`);
  }
  if (recoveredB !== ch.partyB) {
    throw new InvalidCheckpointError(`sigB does not recover to this channel's partyB (got ${recoveredB}, expected ${ch.partyB})`);
  }
  if (BigInt(state.balanceA) + BigInt(state.balanceB) !== ch.depositA + ch.depositB) {
    throw new InvalidCheckpointError("balances don't conserve the channel's total deposits");
  }

  // Normalize to strings for JSON storage — callers may pass bigint fields
  // (e.g. straight from ethers).
  const normalizedState = {
    channelId: state.channelId.toString(),
    nonce: state.nonce.toString(),
    balanceA: state.balanceA.toString(),
    balanceB: state.balanceB.toString(),
  };

  return { checkpoint: { state: normalizedState, sigA, sigB, verifiedAt: new Date().toISOString() }, digest };
}

// Serializes on-chain commitCheckpoint() calls per (paymentChannel, channel)
// — without this, two /checkpoint requests arriving close together for the
// SAME channel (e.g. nonce=1 then nonce=2) can have their async execution
// interleave such that the LATER checkpoint's tx reaches the shared
// NonceManager-wrapped signer first, getting a lower account nonce and
// mining before the earlier one. The earlier (still valid, still first-
// submitted) checkpoint's tx then hits WatchtowerRegistry's
// `nonce <= commitments[...].nonce` guard and reverts with
// NonceNotIncreasing — a confusing, avoidable failure (a real /code-review
// finding), even though impact was bounded (the max committed nonce still
// ends up correct once BOTH land, just not the earlier one, and only if it
// mines second). Keying by channelId alone (not also paymentChannel address)
// is deliberately conservative — this process talks to at most one
// PaymentChannel/registry pair at a time in practice, and over-serializing
// across an unlikely multi-channel collision costs nothing but a little
// latency, unlike under-serializing, which reintroduces the bug.
const commitLocks = new Map<string, Promise<unknown>>();

async function withCommitLock<T>(channelId: string, fn: () => Promise<T>): Promise<T> {
  const prior = commitLocks.get(channelId) ?? Promise.resolve();
  const run = prior.then(fn, fn);
  // Swallow here so one failed commit doesn't poison the chain for the next
  // caller waiting on this key — each caller still observes its own
  // rejection via the awaited `run` below.
  commitLocks.set(
    channelId,
    run.catch(() => undefined)
  );
  return run;
}

export interface SubmitCheckpointResult {
  stored: boolean;
  reason?: string;
  /// Set only when a registry was configured AND this checkpoint was newer
  /// (stored === true): the tx hash of the on-chain commitCheckpoint() call
  /// — see WatchtowerRegistry.sol. Absent (not an error) if no registry was
  /// configured for this watchtower instance.
  onChainCommitTxHash?: string;
  /// Set if a registry WAS configured, the checkpoint WAS stored locally
  /// (the part that actually matters for challenge()-based protection —
  /// see monitor.ts), but the on-chain commitCheckpoint() call itself
  /// failed (e.g. BelowMinStake if the operator forgot to stake, or a
  /// transient RPC error). Deliberately NOT thrown as an exception (a real
  /// /code-review finding: doing so turned a real local-store success into
  /// a misleading HTTP 500, making a caller believe the checkpoint was
  /// rejected entirely when it was in fact accepted and will still protect
  /// the channel via the normal watchtower path — only the STAKE-BACKED
  /// accountability for this specific checkpoint didn't get recorded).
  onChainCommitError?: string;
}

/// Verifies a checkpoint and stores it if valid AND newer than whatever's
/// already stored. If `registry` (a signer-connected WatchtowerRegistry
/// contract) is supplied, ALSO commits `(nonce, hashState digest)`
/// on-chain — see WatchtowerRegistry.sol's doc comment for why: this is
/// what makes a later slash() provable instead of an unverifiable "the
/// watchtower knew" claim. Skipped (not an error) when no registry is
/// configured, e.g. local demos without WATCHTOWER_REGISTRY set — the
/// watchtower still works, just without stake-backed accountability (see
/// README.md).
export async function submitCheckpoint(
  {
    paymentChannel,
    store,
    state,
    registry,
  }: {
    paymentChannel: Contract;
    store: CheckpointStore;
    state: ChannelStateInput;
    registry?: Contract;
  },
  sigA: string,
  sigB: string
): Promise<SubmitCheckpointResult> {
  const { checkpoint, digest } = await verifyCheckpoint({ paymentChannel, state, sigA, sigB });
  const paymentChannelAddress = await paymentChannel.getAddress();
  const stored = store.putIfNewer(paymentChannelAddress, state.channelId, checkpoint);
  if (!stored) {
    return { stored: false, reason: "not newer than an already-stored checkpoint" };
  }

  let onChainCommitTxHash: string | undefined;
  let onChainCommitError: string | undefined;
  if (registry) {
    try {
      // Reuses `digest` from verifyCheckpoint above (same hashState() value,
      // one fewer RPC round-trip) purely as an opaque watermark, never
      // re-derived by WatchtowerRegistry itself (see its doc comment).
      // Serialized per-channel — see withCommitLock's doc comment for why.
      const receipt = await withCommitLock(state.channelId.toString(), async () => {
        const tx = await registry.commitCheckpoint!(state.channelId, state.nonce, digest);
        return tx.wait();
      });
      onChainCommitTxHash = receipt.hash;
    } catch (err) {
      // The checkpoint is ALREADY durably stored locally at this point
      // (store.putIfNewer above) — a failure here must not look like the
      // whole submitCheckpoint() call failed. See onChainCommitError's doc
      // comment for the real bug this fixes.
      onChainCommitError = err instanceof Error ? err.message : String(err);
    }
  }

  return { stored: true, onChainCommitTxHash, onChainCommitError };
}
