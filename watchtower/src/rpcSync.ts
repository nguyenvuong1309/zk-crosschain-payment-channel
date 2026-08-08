// Deploying watchtower/src/e2e_demo.ts against a REAL forked network
// (`anvil --fork-url <Sepolia RPC>`, not plain local Anvil) surfaced a race
// never seen against local Anvil in this whole project: a read
// (`provider.getBalance()`, and by the same mechanism potentially any
// `eth_call`/contract-state read) issued immediately after `tx.wait()`
// resolves can return a value from BEFORE that transaction, even though
// the receipt already confirmed success. Reproduced directly via raw RPC
// (`eth_getBalance`) — this is a real RPC-side eventual-consistency lag on
// that endpoint, not a bug in our contracts or in ethers.js's gas/nonce
// handling. See docs/threat-model.md's "Known issue phát hiện khi test
// trên fork mạng thật" for the full diagnosis.
//
// The existing "fresh provider instance" workaround elsewhere in this
// codebase (for a DIFFERENT, previously-known staleness class against
// plain local Anvil) was NOT sufficient here — a fresh provider still hit
// the same lagging RPC endpoint. What actually works: wait for the RPC's
// reported block number to reach (at least) the block the read should
// reflect, THEN confirm the read has stabilized (two consecutive reads
// agree) before trusting it. Both defenses, layered, since neither alone
// was confirmed sufficient during diagnosis.

import type { Provider, BaseContractMethod, ContractTransactionResponse } from "ethers";

/// Separate, real bug found investigating the SAME "reads/estimates against
/// stale-ish RPC state" family as this file's other helpers: `challenge()`
/// calls in the watchtower e2e demo were failing with a genuine on-chain
/// `OutOfGas` revert (confirmed via `cast run <txhash>` — NOT a client-side
/// encoding issue, the submitted calldata was fully well-formed) — ethers'
/// automatic `estimateGas()` returned a gas limit ~3.7% below what the
/// transaction actually needed by the time it executed. A gas estimate
/// computed against a snapshot of state can under-shoot the real cost if
/// state shifts by execution time (e.g. a storage slot's warm/cold status
/// changing) — the standard mitigation is a safety margin over the raw
/// estimate, not trusting it exactly. See docs/threat-model.md.
///
/// @param method       A contract method bound to a signer (e.g.
///                     `(contract.connect(wallet) as Contract).challenge!`).
/// @param args         Arguments to pass to both the gas estimate and the
///                     actual call.
/// @param bufferBps    Basis points of buffer over the raw estimate (1500 =
///                     15% — generous enough to absorb the ~3.7% shortfall
///                     observed, with real margin left over).
export async function sendWithGasBuffer(
  method: BaseContractMethod,
  args: unknown[],
  { bufferBps = 1500 }: { bufferBps?: number } = {}
): Promise<ContractTransactionResponse> {
  const estimated: bigint = await method.estimateGas(...args);
  const gasLimit = (estimated * BigInt(10_000 + bufferBps)) / 10_000n;
  return method(...args, { gasLimit }) as Promise<ContractTransactionResponse>;
}

/// Polls `provider.getBlockNumber()` until it's >= `targetBlock` (e.g. a
/// transaction's or event's own `receipt.blockNumber`) — the RPC endpoint
/// itself has to agree it's caught up to that block before any subsequent
/// read against it can be trusted.
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

/// Calls `read()` repeatedly until two consecutive calls agree (compared via
/// JSON.stringify with a bigint-safe replacer), or gives up and returns the
/// last value after `maxAttempts` — second line of defense on top of
/// `waitForBlockAtLeast`, for whatever residual staleness a block-number
/// check alone doesn't catch (see this file's header comment: neither
/// mechanism alone was confirmed sufficient during diagnosis).
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
  return previous; // never stabilized within maxAttempts — best effort, caller decides whether that's fatal
}

/// Convenience wrapper for the common case: after a transaction confirms
/// (or an event fires) at `blockNumber`, wait for the RPC to catch up to
/// that block AND for `read()` to stabilize before trusting its result.
export async function readConfirmed<T>(
  provider: Provider,
  blockNumber: number,
  read: () => Promise<T>,
  opts?: { blockWait?: Parameters<typeof waitForBlockAtLeast>[2]; stableWait?: Parameters<typeof readUntilStable>[1] }
): Promise<T> {
  await waitForBlockAtLeast(provider, blockNumber, opts?.blockWait);
  return readUntilStable(read, opts?.stableWait);
}
