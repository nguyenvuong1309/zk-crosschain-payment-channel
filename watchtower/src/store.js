// Persistent checkpoint store — the watchtower's entire "memory" of what the
// latest MUTUALLY co-signed state for each channel is. Keyed by
// `${paymentChannelAddress}:${channelId}` so one watchtower instance can
// safely watch multiple deployments without collisions.
//
// This is a plain JSON file for the demo (see PLAN.md Milestone 4) — a real
// deployment would use a real database, but the trust model is unaffected:
// what matters is that every checkpoint stored here was independently
// signature-verified before being accepted (see checkpoint.js), not how
// it's persisted.

const fs = require("fs");
const path = require("path");

const DEFAULT_STORE_PATH = path.join(__dirname, "..", "checkpoints.json");

class CheckpointStore {
  constructor(storePath = DEFAULT_STORE_PATH) {
    this.storePath = storePath;
    this.data = this._load();
  }

  _load() {
    if (!fs.existsSync(this.storePath)) return {};
    return JSON.parse(fs.readFileSync(this.storePath, "utf8"));
  }

  _save() {
    fs.writeFileSync(this.storePath, JSON.stringify(this.data, null, 2));
  }

  _key(paymentChannelAddress, channelId) {
    return `${paymentChannelAddress.toLowerCase()}:${channelId}`;
  }

  /// Returns the latest checkpoint for a channel, or undefined if none stored.
  getLatest(paymentChannelAddress, channelId) {
    return this.data[this._key(paymentChannelAddress, channelId)];
  }

  /// Stores a checkpoint IF its nonce is strictly newer than whatever's
  /// currently stored (or nothing is stored yet). Returns true if stored.
  /// Caller is responsible for verifying signatures BEFORE calling this —
  /// see checkpoint.js.
  putIfNewer(paymentChannelAddress, channelId, checkpoint) {
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

module.exports = { CheckpointStore, DEFAULT_STORE_PATH };
