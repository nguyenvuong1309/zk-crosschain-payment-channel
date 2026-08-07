#!/usr/bin/env node
// Prints a JSON key-ownership signature for one of this demo's two known
// EdDSA private keys (DEFAULT_PRIV_KEY_A/B, see input_gen/build_channel_state_input.js),
// bound to a specific PaymentChannel deployment/channel/party. Invoked via
// Foundry's `vm.ffi` from contracts/test/ChannelStateProof.t.sol so the
// signature always matches whatever address Forge actually deployed the
// contract at (same reasoning as prove_and_export.sh's domain binding).
//
// Usage: sign_key_ownership.js <A|B> <contractAddress> <chainId> <channelId> <partyAddress>

const path = require("path");
const { signKeyOwnership } = require(path.join(__dirname, "..", "input_gen", "eddsa_ownership"));
const { DEFAULT_PRIV_KEY_A, DEFAULT_PRIV_KEY_B } = require(path.join(__dirname, "..", "input_gen", "build_channel_state_input"));

async function main() {
  const [, , who, contractAddress, chainId, channelId, party] = process.argv;
  const privKey = who === "A" ? DEFAULT_PRIV_KEY_A : who === "B" ? DEFAULT_PRIV_KEY_B : null;
  if (!privKey) throw new Error(`unknown party label ${JSON.stringify(who)}, expected "A" or "B"`);

  const sig = await signKeyOwnership({
    privKey,
    contractAddress,
    chainId: BigInt(chainId),
    channelId: BigInt(channelId),
    party,
  });

  process.stdout.write(
    JSON.stringify({
      pubKeyX: sig.pubKeyX.toString(),
      pubKeyY: sig.pubKeyY.toString(),
      R8x: sig.R8x.toString(),
      R8y: sig.R8y.toString(),
      S: sig.S.toString(),
    })
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
