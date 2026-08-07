// Off-chain helper: computes the Schnorr-style Baby Jubjub "key ownership"
// signature PaymentChannel.sol's open()/join() now require alongside a
// non-zero registered EdDSA public key (fixes docs/threat-model.md
// assumption #5 — a registered key previously wasn't checked to actually
// belong to the caller).
//
// Deliberately NOT circomlib's EdDSA-Poseidon scheme used inside
// channel_state.circom (that needs Poseidon on-chain, which is expensive as
// plain EVM opcodes) — this is a plain Schnorr signature over the SAME Baby
// Jubjub curve/keypair, with a keccak256 Fiat-Shamir challenge so
// PaymentChannel.sol can verify it with nothing but native EVM opcodes + the
// modexp precompile. See contracts/src/BabyJubJub.sol and
// PaymentChannel.sol::_verifyKeyOwnership for the on-chain half.

const circomlibjs = require("circomlibjs");
const { Scalar } = require("ffjavascript");
const createBlakeHash = require("blake-hash");
// ethers v5 is what's actually installed here (transitively, via snarkjs) —
// v5's API lives under `ethers.utils`, unlike v6's flat exports.
const { utils: ethersUtils } = require("ethers");
const { defaultAbiCoder, keccak256, hexZeroPad, hexlify, concat } = ethersUtils;

const SUB_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;

function pruneBuffer(buff) {
  buff[0] &= 0xf8;
  buff[31] &= 0x7f;
  buff[31] |= 0x40;
  return buff;
}

// Derives the same scalar circomlibjs's `eddsa.prv2pub` uses internally, so
// the public key here is exactly the one registered/used for off-chain
// signing (see circomlibjs's src/eddsa.js `prv2pub`).
function privToScalar(privKey) {
  const sBuff = pruneBuffer(createBlakeHash("blake512").update(Buffer.from(privKey)).digest());
  const s = Scalar.fromRprLE(sBuff, 0, 32);
  return BigInt(Scalar.shr(s, 3).toString());
}

function abiEncode(types, values) {
  return defaultAbiCoder.encode(types, values);
}

function toBytes32(x) {
  return hexZeroPad(hexlify(x), 32);
}

/// @param opts.privKey         Buffer — same raw EdDSA private key seed passed to circomlibjs
/// @param opts.contractAddress hex address of the PaymentChannel deployment
/// @param opts.chainId         bigint
/// @param opts.channelId       bigint — for `open()`, this is the channelId the contract
///                             WILL assign (== current `nextChannelId`); for `join()`,
///                             the existing channel's id
/// @param opts.party           address of msg.sender (the party registering this key)
async function signKeyOwnership(opts) {
  const eddsa = await circomlibjs.buildEddsa();
  const F = eddsa.F;
  const { privKey, contractAddress, chainId, channelId, party } = opts;

  const sk = privToScalar(privKey);
  const pub = eddsa.prv2pub(privKey);
  const pubKeyX = BigInt(F.toObject(pub[0]).toString());
  const pubKeyY = BigInt(F.toObject(pub[1]).toString());

  // Deterministic nonce: derived from the private scalar + the same context
  // (minus R8, which doesn't exist yet) the final challenge binds to — never
  // reused across channels/deployments/parties, so no randomness needed.
  const nonceContext = keccak256(
    abiEncode(
      ["string", "address", "uint256", "uint256", "address", "uint256", "uint256"],
      ["EDDSA_OWNERSHIP_NONCE", contractAddress, chainId, channelId, party, pubKeyX, pubKeyY]
    )
  );
  const r = BigInt(keccak256(concat([toBytes32(sk), nonceContext]))) % SUB_ORDER;

  const R8 = eddsa.babyJub.mulPointEscalar(eddsa.babyJub.Base8, r);
  const R8x = BigInt(F.toObject(R8[0]).toString());
  const R8y = BigInt(F.toObject(R8[1]).toString());

  // Must mirror PaymentChannel.sol::_verifyKeyOwnership's challenge exactly.
  const challenge =
    BigInt(
      keccak256(
        abiEncode(
          ["string", "address", "uint256", "uint256", "address", "uint256", "uint256", "uint256", "uint256"],
          ["EDDSA_OWNERSHIP", contractAddress, chainId, channelId, party, pubKeyX, pubKeyY, R8x, R8y]
        )
      )
    ) % SUB_ORDER;

  const S = (r + challenge * sk) % SUB_ORDER;

  return { pubKeyX, pubKeyY, R8x, R8y, S };
}

module.exports = { signKeyOwnership, privToScalar, SUB_ORDER };
