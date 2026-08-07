// Watches a PaymentChannel deployment for `ChannelClosedUnilaterally` /
// `ChannelChallenged` events and, if the resulting on-chain state is STALER
// than what this watchtower has checkpointed for that channel, automatically
// submits the correct newer state via `challenge()` — protecting whichever
// party is offline. See PLAN.md Milestone 4 and docs/threat-model.md #2.
//
// This only works because `challenge()` is NOT `onlyParty` (see its doc
// comment in PaymentChannel.sol) — the watchtower submits the tx itself,
// authorized by the two signatures it was checkpointed with, never by
// holding either party's key.

const PaymentChannelStatus = { UNINITIALIZED: 0, ACTIVE: 1, CHALLENGE_PERIOD: 2, CLOSED: 3 };

/// @param opts.paymentChannel ethers.Contract, READ instance (provider-connected)
/// @param opts.wallet         ethers.Wallet — funded account the watchtower
///                            submits `challenge()` transactions from (does
///                            NOT need to be either party)
/// @param opts.store          CheckpointStore
/// @param opts.onAction       optional callback(info) for logging/testing,
///                            called whenever the watchtower submits (or
///                            decides not to submit) a rescue challenge
async function reactToChannel({ paymentChannel, wallet, store, channelId, onAction }) {
  const paymentChannelAddress = await paymentChannel.getAddress();
  const ch = await paymentChannel.channels(channelId);

  if (Number(ch.status) !== PaymentChannelStatus.CHALLENGE_PERIOD) {
    onAction?.({ channelId, action: "skip", reason: `status is ${ch.status}, not CHALLENGE_PERIOD` });
    return;
  }

  const latestBlock = await paymentChannel.runner.provider.getBlock("latest");
  if (BigInt(latestBlock.timestamp) >= ch.challengeExpiry) {
    onAction?.({ channelId, action: "skip", reason: "challenge window already closed" });
    return;
  }

  const checkpoint = store.getLatest(paymentChannelAddress, channelId);
  if (!checkpoint) {
    onAction?.({ channelId, action: "skip", reason: "no checkpoint on file for this channel" });
    return;
  }

  if (BigInt(checkpoint.state.nonce) <= ch.nonce) {
    onAction?.({ channelId, action: "skip", reason: `checkpoint nonce ${checkpoint.state.nonce} is not newer than on-chain nonce ${ch.nonce}` });
    return;
  }

  onAction?.({
    channelId,
    action: "challenging",
    onChainNonce: ch.nonce.toString(),
    checkpointNonce: checkpoint.state.nonce.toString(),
  });

  const tx = await paymentChannel.connect(wallet).challenge(checkpoint.state, checkpoint.sigA, checkpoint.sigB);
  const receipt = await tx.wait();

  onAction?.({ channelId, action: "challenged", txHash: receipt.hash });
  return receipt;
}

/// Subscribes to the two events that can leave a channel in a disputable
/// state and reacts to each. Returns a function to stop listening.
function startMonitoring({ paymentChannel, wallet, store, onAction }) {
  const handler = (channelId) => {
    reactToChannel({ paymentChannel, wallet, store, channelId, onAction }).catch((err) => {
      onAction?.({ channelId, action: "error", error: err.message });
    });
  };

  const onClosedUnilaterally = (channelId) => handler(channelId);
  const onChallenged = (channelId) => handler(channelId);

  paymentChannel.on("ChannelClosedUnilaterally", onClosedUnilaterally);
  paymentChannel.on("ChannelChallenged", onChallenged);

  return () => {
    paymentChannel.off("ChannelClosedUnilaterally", onClosedUnilaterally);
    paymentChannel.off("ChannelChallenged", onChallenged);
  };
}

module.exports = { startMonitoring, reactToChannel, PaymentChannelStatus };
