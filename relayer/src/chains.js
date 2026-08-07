// Loads relayer/chains.config.json and resolves each chain's RPC URL /
// deployer key from environment variables (see .env.example) — the single
// place that turns "named chain" into "actual connection info", so
// deploy.js / index.js / e2e_demo.js never hardcode chainA/chainB RPC
// ports or fall back to the Anvil demo key by name. Add a new chain (a 3rd
// network, or repointing an existing name at a real testnet) by editing
// chains.config.json + .env only.

const fs = require("fs");
const path = require("path");

const CONFIG_PATH = path.join(__dirname, "..", "chains.config.json");

// Anvil's well-known default account #0 private key — safe fallback ONLY
// for a local Anvil instance (anyone can derive it, it's public). Chains
// pointed at anything else must set their deployerKeyEnv in .env; see the
// warning in resolveChains() below.
const ANVIL_DEMO_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

function isLocalhost(rpcUrl) {
  return rpcUrl.includes("127.0.0.1") || rpcUrl.includes("localhost");
}

/// Reads chains.config.json and resolves each entry's rpcUrl/deployerKey
/// from its configured env vars (falling back to rpcDefault / the Anvil
/// demo key). Returns { <name>: { rpcUrl, deployerKey, lightClient } }.
function resolveChains(configPath = CONFIG_PATH) {
  const raw = JSON.parse(fs.readFileSync(configPath, "utf8"));
  const resolved = {};

  for (const [name, cfg] of Object.entries(raw.chains)) {
    const rpcUrl = process.env[cfg.rpcEnv] ?? cfg.rpcDefault;
    const deployerKey = process.env[cfg.deployerKeyEnv] ?? process.env.DEPLOYER_PRIVATE_KEY ?? ANVIL_DEMO_KEY;

    if (deployerKey === ANVIL_DEMO_KEY && !isLocalhost(rpcUrl)) {
      console.error(
        `[!] ${name}: ${cfg.rpcEnv} points somewhere other than localhost, but no ${cfg.deployerKeyEnv} is set — ` +
          `about to deploy using Anvil's PUBLIC well-known demo key. If this is a real network, stop and set ` +
          `${cfg.deployerKeyEnv} (or DEPLOYER_PRIVATE_KEY) in .env (see .env.example) first.`
      );
    }

    resolved[name] = { rpcUrl, deployerKey, lightClient: cfg.lightClient === true };
  }

  return resolved;
}

module.exports = { resolveChains, ANVIL_DEMO_KEY, isLocalhost, CONFIG_PATH };
