// Watchtower — Milestone 4 (see PLAN.md, docs/threat-model.md #2).
//
// A third party that:
//   1. Accepts checkpointed (signature-verified) copies of the latest
//      mutually co-signed ChannelState for channels it's asked to watch
//      (POST /checkpoint — see server.js).
//   2. Watches PaymentChannel for `ChannelClosedUnilaterally` /
//      `ChannelChallenged` events (see monitor.js).
//   3. If the resulting on-chain state is staler than what it has
//      checkpointed, automatically submits the correct newer state via
//      `challenge()` — protecting whichever party is offline, without ever
//      holding either party's private key (challenge() is signature-
//      authorized, not `onlyParty` — see PaymentChannel.sol).
//
// This only affects LIVENESS for the offline party's protection — it does
// NOT weaken the channel's safety: `challenge()` still requires two valid
// signatures over the state being submitted, exactly as if a party
// submitted it themselves. A malicious or crashed watchtower can only fail
// to protect an offline party (same risk as having no watchtower at all);
// it can never forge a challenge or steal funds.

require("dotenv").config();
const path = require("path");
const { ethers } = require("ethers");
const artifacts = require("./artifacts");
const { CheckpointStore } = require("./store");
const { createServer } = require("./server");
const { startMonitoring, reactToChannel } = require("./monitor");

const RPC_URL = process.env.WATCHTOWER_RPC_URL ?? "http://127.0.0.1:8545";
const CONTRACT_ADDRESS = process.env.WATCHTOWER_CONTRACT;
const PORT = Number(process.env.WATCHTOWER_PORT ?? 8787);
// Falls back to Anvil's well-known demo account #2 so the local demo needs
// zero setup — any funded account works, the watchtower needs no special
// role (see challenge()'s doc comment). Set WATCHTOWER_PRIVATE_KEY in .env
// (see .env.example) for anything else, a real testnet in particular.
const ANVIL_DEMO_KEY = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";
const WATCHTOWER_KEY = process.env.WATCHTOWER_PRIVATE_KEY ?? ANVIL_DEMO_KEY;

if (WATCHTOWER_KEY === ANVIL_DEMO_KEY && !RPC_URL.includes("127.0.0.1") && !RPC_URL.includes("localhost")) {
  console.error(
    "[!] WATCHTOWER_RPC_URL points somewhere other than localhost, but no WATCHTOWER_PRIVATE_KEY is set — " +
      "about to submit transactions using Anvil's PUBLIC well-known demo key. If this is a real network, stop " +
      "and set WATCHTOWER_PRIVATE_KEY in .env (see .env.example) first."
  );
}

async function main() {
  if (!CONTRACT_ADDRESS) {
    throw new Error("set WATCHTOWER_CONTRACT to the PaymentChannel address to watch");
  }

  const provider = new ethers.JsonRpcProvider(RPC_URL);
  const wallet = new ethers.Wallet(WATCHTOWER_KEY, provider);
  const { abi } = artifacts.PaymentChannel();
  const paymentChannel = new ethers.Contract(CONTRACT_ADDRESS, abi, provider);

  const store = new CheckpointStore(process.env.WATCHTOWER_STORE_PATH ?? path.join(__dirname, "..", "checkpoints.json"));

  const onAction = (info) => console.error(`[watchtower] channel ${info.channelId}: ${info.action}${info.reason ? ` (${info.reason})` : ""}`);

  const server = createServer({ paymentChannel, store });
  server.listen(PORT, () => console.error(`[watchtower] checkpoint API listening on :${PORT}`));

  startMonitoring({ paymentChannel, wallet, store, onAction });
  console.error(`[watchtower] watching ${CONTRACT_ADDRESS} on ${RPC_URL} as ${wallet.address}`);
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}

module.exports = { reactToChannel };
