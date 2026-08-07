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

const { ethers } = require("ethers");

class InvalidCheckpointError extends Error {}

/// @param opts.paymentChannel ethers.Contract (read-only is fine) for the
///                            PaymentChannel this checkpoint is for
/// @param opts.state          { channelId, nonce, balanceA, balanceB }
/// @param opts.sigA/sigB      hex signature strings
async function verifyCheckpoint({ paymentChannel, state, sigA, sigB }) {
  const ch = await paymentChannel.channels(state.channelId);
  if (ch.partyA === ethers.ZeroAddress) {
    throw new InvalidCheckpointError(`channel ${state.channelId} does not exist`);
  }

  // Mirrors PaymentChannel.sol::_verifyBothSignatures exactly — same digest
  // (hashState, domain-separated), same personal-sign recovery.
  const digest = await paymentChannel.hashState(state);
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

/// Verifies a checkpoint and stores it if valid AND newer than whatever's
/// already stored. Returns { stored: boolean, reason?: string }.
async function submitCheckpoint({ paymentChannel, store, state }, sigA, sigB) {
  const checkpoint = await verifyCheckpoint({ paymentChannel, state, sigA, sigB });
  const paymentChannelAddress = await paymentChannel.getAddress();
  const stored = store.putIfNewer(paymentChannelAddress, state.channelId, checkpoint);
  return { stored, reason: stored ? undefined : "not newer than an already-stored checkpoint" };
}

module.exports = { verifyCheckpoint, submitCheckpoint, InvalidCheckpointError };
