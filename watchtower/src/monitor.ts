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

import type { Contract, Wallet, ContractTransactionReceipt } from "ethers";
import type { CheckpointStore } from "./store";

export const PaymentChannelStatus = { UNINITIALIZED: 0, ACTIVE: 1, CHALLENGE_PERIOD: 2, CLOSED: 3 } as const;

export interface ActionInfo {
  channelId: string | bigint | number;
  action: "skip" | "challenging" | "challenged" | "error";
  reason?: string;
  onChainNonce?: string;
  checkpointNonce?: string;
  txHash?: string;
  error?: string;
}

export type OnAction = (info: ActionInfo) => void;

/// @param opts.paymentChannel ethers.Contract, READ instance (provider-connected)
/// @param opts.wallet         ethers.Wallet — funded account the watchtower
///                            submits `challenge()` transactions from (does
///                            NOT need to be either party)
/// @param opts.store          CheckpointStore
/// @param opts.onAction       optional callback(info) for logging/testing,
///                            called whenever the watchtower submits (or
///                            decides not to submit) a rescue challenge
export async function reactToChannel({
  paymentChannel,
  wallet,
  store,
  channelId,
  onAction,
}: {
  paymentChannel: Contract;
  wallet: Wallet;
  store: CheckpointStore;
  channelId: string | bigint | number;
  onAction?: OnAction;
}): Promise<ContractTransactionReceipt | undefined> {
  const paymentChannelAddress = await paymentChannel.getAddress();
  const ch = await paymentChannel.channels!(channelId);

  if (Number(ch.status) !== PaymentChannelStatus.CHALLENGE_PERIOD) {
    onAction?.({ channelId, action: "skip", reason: `status is ${ch.status}, not CHALLENGE_PERIOD` });
    return;
  }

  const provider = paymentChannel.runner!.provider!;
  const latestBlock = await provider.getBlock("latest");
  if (BigInt(latestBlock!.timestamp) >= ch.challengeExpiry) {
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

  const tx = await (paymentChannel.connect(wallet) as Contract).challenge!(checkpoint.state, checkpoint.sigA, checkpoint.sigB);
  const receipt: ContractTransactionReceipt = await tx.wait();

  onAction?.({ channelId, action: "challenged", txHash: receipt.hash });
  return receipt;
}

/// Subscribes to the two events that can leave a channel in a disputable
/// state and reacts to each. Returns a function to stop listening.
export function startMonitoring({
  paymentChannel,
  wallet,
  store,
  onAction,
}: {
  paymentChannel: Contract;
  wallet: Wallet;
  store: CheckpointStore;
  onAction?: OnAction;
}): () => void {
  const handler = (channelId: string | bigint | number) => {
    reactToChannel({ paymentChannel, wallet, store, channelId, onAction }).catch((err: Error) => {
      onAction?.({ channelId, action: "error", error: err.message });
    });
  };

  const onClosedUnilaterally = (channelId: string | bigint | number) => handler(channelId);
  const onChallenged = (channelId: string | bigint | number) => handler(channelId);

  paymentChannel.on("ChannelClosedUnilaterally", onClosedUnilaterally);
  paymentChannel.on("ChannelChallenged", onChallenged);

  return () => {
    paymentChannel.off("ChannelClosedUnilaterally", onClosedUnilaterally);
    paymentChannel.off("ChannelChallenged", onChallenged);
  };
}
