// Off-chain BLS12-381 signing for the demo validator committee.
// Computes the SAME message-to-G2-point mapping LightClientVerifierBLS.sol
// computes on-chain (see that contract's `_hashToG2` doc comment), signs
// with each participating validator's real private key, and aggregates
// (G2 point addition) into a single signature ready for `updateState()`.
//
// Usage: node sign.js <chainId> <blockNumber> <stateRoot> <participantBitmap>
//   e.g. node sign.js 31337 1 12345 7   # bitmap 0b111 = validators 0,1,2

const { bls12_381 } = require("@noble/curves/bls12-381.js");
const { ethers } = require("ethers");
const keys = require("./keys.json");

const NUM_VALIDATORS = 5;

function fpHex(n) {
  return n.toString(16).padStart(128, "0");
}

function g2Hex(point) {
  const p = point.toAffine ? point.toAffine() : point;
  return "0x" + fpHex(p.x.c0) + fpHex(p.x.c1) + fpHex(p.y.c0) + fpHex(p.y.c1);
}

/// Mirrors LightClientVerifierBLS.sol::_hashToG2 exactly.
function messagePoint(chainId, blockNumber, stateRoot) {
  const u0 = BigInt(
    ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["string", "uint256", "uint256", "uint256"], ["BLS_MSG_U0", chainId, blockNumber, stateRoot]))
  );
  const u1 = BigInt(
    ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["string", "uint256", "uint256", "uint256"], ["BLS_MSG_U1", chainId, blockNumber, stateRoot]))
  );
  return bls12_381.G2.mapToCurve([u0, u1]);
}

/// @param opts.chainId/blockNumber/stateRoot  bigint-able values
/// @param opts.participantBitmap              bigint/number — bit i set => validator i signs
/// @returns { aggSig: "0x..." (256 bytes), participantBitmap }
function signAggregate({ chainId, blockNumber, stateRoot, participantBitmap }) {
  const M = messagePoint(chainId, blockNumber, stateRoot);

  let aggSig = null;
  for (let i = 0; i < NUM_VALIDATORS; i++) {
    if (!((BigInt(participantBitmap) >> BigInt(i)) & 1n)) continue;
    const scalar = BigInt(keys.validators[i].secretKey);
    const sig = M.multiply(scalar);
    aggSig = aggSig === null ? sig : aggSig.add(sig);
  }
  if (aggSig === null) throw new Error("participantBitmap selects zero validators");

  return { aggSig: g2Hex(aggSig), participantBitmap: participantBitmap.toString() };
}

if (require.main === module) {
  const [, , chainId, blockNumber, stateRoot, participantBitmap] = process.argv;
  if (!chainId || !blockNumber || !stateRoot || !participantBitmap) {
    console.error("usage: node sign.js <chainId> <blockNumber> <stateRoot> <participantBitmap>");
    process.exit(1);
  }
  const result = signAggregate({
    chainId: BigInt(chainId),
    blockNumber: BigInt(blockNumber),
    stateRoot: BigInt(stateRoot),
    participantBitmap: BigInt(participantBitmap),
  });
  console.log(JSON.stringify(result));
}

module.exports = { signAggregate, messagePoint };
