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
}): Promise<Checkpoint> {
  const ch = await paymentChannel.getChannel!(state.channelId);
  if (ch.partyA === ethers.ZeroAddress) {
    throw new InvalidCheckpointError(`channel ${state.channelId} does not exist`);
  }

  // Mirrors PaymentChannel.sol::_verifyBothSignatures exactly — same digest
  // (hashState, domain-separated), same personal-sign recovery.
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

  return { state: normalizedState, sigA, sigB, verifiedAt: new Date().toISOString() };
}

export interface SubmitCheckpointResult {
  stored: boolean;
  reason?: string;
  /// Set only when a registry was configured AND this checkpoint was newer
  /// (stored === true): the tx hash of the on-chain commitCheckpoint() call
  /// — see WatchtowerRegistry.sol. Absent (not an error) if no registry was
  /// configured for this watchtower instance.
  onChainCommitTxHash?: string;
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
  const checkpoint = await verifyCheckpoint({ paymentChannel, state, sigA, sigB });
  const paymentChannelAddress = await paymentChannel.getAddress();
  const stored = store.putIfNewer(paymentChannelAddress, state.channelId, checkpoint);
  if (!stored) {
    return { stored: false, reason: "not newer than an already-stored checkpoint" };
  }

  let onChainCommitTxHash: string | undefined;
  if (registry) {
    // Same digest formula PaymentChannel.hashState()/verifyCheckpoint above
    // used to check sigA/sigB — reused here purely as an opaque watermark,
    // never re-derived by WatchtowerRegistry itself (see its doc comment).
    const digest: string = await paymentChannel.hashState!(state);
    const tx = await registry.commitCheckpoint!(state.channelId, state.nonce, digest);
    const receipt = await tx.wait();
    onChainCommitTxHash = receipt.hash;
  }

  return { stored: true, onChainCommitTxHash };
}
