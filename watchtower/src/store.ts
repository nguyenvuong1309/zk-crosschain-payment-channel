// Persistent checkpoint store — the watchtower's entire "memory" of what the
// latest MUTUALLY co-signed state for each channel is. Keyed by
// `${paymentChannelAddress}:${channelId}` so one watchtower instance can
// safely watch multiple deployments without collisions.
//
// This is a plain JSON file for the demo (see PLAN.md Milestone 4) — a real
// deployment would use a real database, but the trust model is unaffected:
// what matters is that every checkpoint stored here was independently
// signature-verified before being accepted (see checkpoint.ts), not how
// it's persisted.

import fs from "fs";
import path from "path";

const DEFAULT_STORE_PATH = path.join(__dirname, "..", "checkpoints.json");

/// A ChannelState with all numeric fields as decimal strings — the shape
/// checkpoints are normalized to before persisting (JSON has no bigint).
export interface StoredChannelState {
  channelId: string;
  nonce: string;
  balanceA: string;
  balanceB: string;
}

export interface Checkpoint {
  state: StoredChannelState;
  sigA: string;
  sigB: string;
  verifiedAt: string;
}

type StoreData = Record<string, Checkpoint>;

export class CheckpointStore {
  private storePath: string;
  private data: StoreData;

  constructor(storePath: string = DEFAULT_STORE_PATH) {
    this.storePath = storePath;
    this.data = this._load();
  }

  private _load(): StoreData {
    if (!fs.existsSync(this.storePath)) return {};
    return JSON.parse(fs.readFileSync(this.storePath, "utf8"));
  }

  private _save(): void {
    fs.writeFileSync(this.storePath, JSON.stringify(this.data, null, 2));
  }

  private _key(paymentChannelAddress: string, channelId: string | bigint | number): string {
    return `${paymentChannelAddress.toLowerCase()}:${channelId}`;
  }

  /// Returns the latest checkpoint for a channel, or undefined if none stored.
  getLatest(paymentChannelAddress: string, channelId: string | bigint | number): Checkpoint | undefined {
    return this.data[this._key(paymentChannelAddress, channelId)];
  }

  /// Stores a checkpoint IF its nonce is strictly newer than whatever's
  /// currently stored (or nothing is stored yet). Returns true if stored.
  /// Caller is responsible for verifying signatures BEFORE calling this —
  /// see checkpoint.ts.
  putIfNewer(paymentChannelAddress: string, channelId: string | bigint | number, checkpoint: Checkpoint): boolean {
    const key = this._key(paymentChannelAddress, channelId);
    const existing = this.data[key];
    if (existing && BigInt(existing.state.nonce) >= BigInt(checkpoint.state.nonce)) {
      return false;
    }
    this.data[key] = checkpoint;
    this._save();
    return true;
  }
}

export { DEFAULT_STORE_PATH };
