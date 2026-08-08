// Ported from watchtower/src/rpcSync.ts (same repo, self-contained package
// convention — see that file's header comment for the full diagnosis).
// Two real, separate bugs surfaced testing watchtower/'s e2e demo against
// both a forked-mainnet RPC and plain local Anvil:
//   1. A read (`provider.getBalance()`, and by the same mechanism
//      potentially any `eth_call`/contract-state read) issued right after
//      `tx.wait()` resolves can return a value from BEFORE that
//      transaction, on a forked/real RPC — even a "fresh provider
//      instance" wasn't sufficient. Fix: confirm the RPC's block number
//      has caught up, then retry the read until two consecutive calls
//      agree.
//   2. `estimateGas()`'s result can run out ~a few percent short of what a
//      transaction actually needs by execution time (confirmed via
//      `cast run <txhash>`: a real on-chain `OutOfGas`, not a client-side
//      encoding bug) — needs a safety margin over the raw estimate.
// Both apply equally to relayer/'s `updateState()` call (the equivalent
// production write path here to watchtower's `challenge()`) — see
// docs/threat-model.md for the full write-up.

import type { Provider, BaseContractMethod, ContractTransactionResponse } from "ethers";

export async function waitForBlockAtLeast(
  provider: Provider,
  targetBlock: number,
  { maxAttempts = 20, delayMs = 250 }: { maxAttempts?: number; delayMs?: number } = {}
): Promise<number> {
  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const current = await provider.getBlockNumber();
    if (current >= targetBlock) return current;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  throw new Error(`RPC never reached block ${targetBlock} after ${maxAttempts} attempts — endpoint may be stuck or badly lagging`);
}

export async function readUntilStable<T>(
  read: () => Promise<T>,
  { maxAttempts = 5, delayMs = 300 }: { maxAttempts?: number; delayMs?: number } = {}
): Promise<T> {
  const stringify = (v: T) => JSON.stringify(v, (_key, value) => (typeof value === "bigint" ? value.toString() : value));

  let previous = await read();
  let previousStr = stringify(previous);
  for (let attempt = 1; attempt < maxAttempts; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    const current = await read();
    const currentStr = stringify(current);
    if (currentStr === previousStr) return current;
    previous = current;
    previousStr = currentStr;
  }
  return previous;
}

export async function readConfirmed<T>(
  provider: Provider,
  blockNumber: number,
  read: () => Promise<T>,
  opts?: { blockWait?: Parameters<typeof waitForBlockAtLeast>[2]; stableWait?: Parameters<typeof readUntilStable>[1] }
): Promise<T> {
  await waitForBlockAtLeast(provider, blockNumber, opts?.blockWait);
  return readUntilStable(read, opts?.stableWait);
}

/// @param bufferBps Basis points of buffer over the raw gas estimate (1500
///                  = 15% — generous enough to absorb the ~3.7% shortfall
///                  observed in practice, with real margin left over).
export async function sendWithGasBuffer(
  method: BaseContractMethod,
  args: unknown[],
  { bufferBps = 1500 }: { bufferBps?: number } = {}
): Promise<ContractTransactionResponse> {
  const estimated: bigint = await method.estimateGas(...args);
  const gasLimit = (estimated * BigInt(10_000 + bufferBps)) / 10_000n;
  return method(...args, { gasLimit }) as Promise<ContractTransactionResponse>;
}
