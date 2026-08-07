// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BLS12381} from "./BLS12381.sol";

/// @title LightClientVerifierBLS
/// @notice Milestone 4's upgrade of the toy cross-chain "light client"
///         (see `LightClientVerifier.sol`, the original EdDSA-Poseidon-ZK-
///         proof version): instead of a Groth16 proof that ≥3-of-5 demo
///         validators EdDSA-signed a Poseidon commitment, this version
///         verifies a REAL BLS12-381 aggregate signature directly on-chain
///         via the EIP-2537 precompiles (live since the Prague/Pectra
///         hardfork) — no ZK circuit involved for this check at all.
///
///         This mirrors how REAL Ethereum light clients actually verify
///         sync committee attestations on L1 (a single aggregate BLS
///         pairing check) — Succinct/Polyhedra-style ZK light clients exist
///         to COMPRESS this check for L2/cross-rollup cost reasons, not
///         because on-chain BLS verification is otherwise impossible.
///
///         STILL a toy committee (see docs/threat-model.md #6): 5 hardcoded
///         demo validator keys (`bls-validators/`), NOT Ethereum's real
///         sync committee. What's genuinely real here is the cryptography
///         (BLS12-381 keys, real aggregate signatures, real pairing check),
///         not the committee's identity/size.
///
///         `stateRoot` remains deliberately opaque (see
///         `LightClientVerifier.sol`'s doc comment) — same scope limits
///         apply.
contract LightClientVerifierBLS {
    uint256 public constant NUM_VALIDATORS = 5;
    uint256 public constant THRESHOLD = 3;

    // 5 demo validators' G1 public keys (EIP-2537 encoding, 128 bytes each)
    // — see bls-validators/keys.json for the corresponding (demo-only,
    // publicly known) private keys used to sign.
    bytes internal constant PUBKEY_0 =
        hex"000000000000000000000000000000000d83338d7fb394505b38d56c16de9a4808d641c2f531393727a40e3bf7de3363239739e084f1b49a70e6d00ed0e32101000000000000000000000000000000000d6a50f308cb3b6a99c8eb7c44ec85b8aadbd536da19eb133f477f3481f9cc4f8ba255774320c5767a8e1041321d1763";
    bytes internal constant PUBKEY_1 =
        hex"00000000000000000000000000000000034fee46a710c5829861f835235d44373ac32548a162f1d397d047a55eb62aa062a33681d6f198525f1da5cdbb826b78000000000000000000000000000000000ade2468e626faf7d58bbfe06cbf6e56dffd81a7c324db475953de501d2b8190cb1e2aa53dc67c57b37b797b8adac798";
    bytes internal constant PUBKEY_2 =
        hex"000000000000000000000000000000000a2a2cc2322c3d76afffac345d4efc88f42ecee42d85c2d7fee1a44667850d0a1b9fe85c4088349b2dd6aa398cd3ce7a00000000000000000000000000000000172bd3c50d882d049f834f37a89cc77601abcfa7c1a41dc22f7812904e7f664223aebc73aa401abb68e30afe22e88895";
    bytes internal constant PUBKEY_3 =
        hex"0000000000000000000000000000000013ed9cc90390f0e406272ed3d0b708620af9dba3c74dbf12cd7cac42bb522f1cc818a5b0a9b3cb9c4ee0db2e038b000f00000000000000000000000000000000046d85b5bf3a7f1e682acdaaf5152a8e41738d59b4fc38cc6c7f596290b89517f39de1e2c3b62dca96fdf577c4278f32";
    bytes internal constant PUBKEY_4 =
        hex"0000000000000000000000000000000004b610adb70dc82db8a08bb87311594e2ce43120faa5f7e9f795b531c6254ed8a879ce1557ddbdd7fb4601e604d412d80000000000000000000000000000000019f1a6e3072f813dbf117d33f73174eb2dfbfc0faf55de4d72952e80b54fb4e0d9857381bc154dec8087227d54049365";

    // -G1 (negated generator) — for the pairing check
    // e(aggPubkey, M) * e(-G1, aggSig) == 1  <=>  e(aggPubkey, M) == e(G1, aggSig)
    bytes internal constant NEG_G1_GENERATOR =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    mapping(uint256 => uint256) public trustedStateRoot; // chainId => latest attested stateRoot
    mapping(uint256 => uint256) public trustedBlockNumber; // chainId => latest attested blockNumber

    event StateRootUpdated(uint256 indexed chainId, uint256 blockNumber, uint256 stateRoot);

    error StaleBlockNumber();
    error InsufficientQuorum();
    error InvalidAggregateSignature();
    error InvalidSignatureLength();

    /// @notice Submits a BLS aggregate signature attesting to
    ///         (chainId, blockNumber, stateRoot), updating
    ///         `trustedStateRoot[chainId]` if the quorum and signature check
    ///         pass and `blockNumber` is newer than the last accepted one.
    /// @param participantBitmap bit `i` set means validator `i` (0-4) signed.
    /// @param aggSig The sum (G2 point addition) of every participating
    ///        validator's individual signature over the SAME message point
    ///        — see `bls-validators/sign.js` for how this is produced
    ///        off-chain.
    function updateState(uint256 chainId, uint256 blockNumber, uint256 stateRoot, uint256 participantBitmap, bytes calldata aggSig)
        external
    {
        if (blockNumber <= trustedBlockNumber[chainId]) revert StaleBlockNumber();
        if (_popcount(participantBitmap) < THRESHOLD) revert InsufficientQuorum();
        if (aggSig.length != 256) revert InvalidSignatureLength();

        bytes memory aggPubkey = _aggregatePubkeys(participantBitmap);
        bytes memory messagePoint = _hashToG2(chainId, blockNumber, stateRoot);

        bytes memory pairingInput = abi.encodePacked(aggPubkey, messagePoint, NEG_G1_GENERATOR, aggSig);
        if (!BLS12381.pairingCheck(pairingInput)) revert InvalidAggregateSignature();

        trustedStateRoot[chainId] = stateRoot;
        trustedBlockNumber[chainId] = blockNumber;

        emit StateRootUpdated(chainId, blockNumber, stateRoot);
    }

    /// @dev Sums the G1 public keys of every validator flagged in
    ///      `participantBitmap` — real elliptic-curve point addition via the
    ///      G1ADD precompile, not a placeholder.
    function _aggregatePubkeys(uint256 participantBitmap) internal view returns (bytes memory agg) {
        bytes[5] memory pubkeys = [PUBKEY_0, PUBKEY_1, PUBKEY_2, PUBKEY_3, PUBKEY_4];
        bool started = false;
        for (uint256 i = 0; i < NUM_VALIDATORS; i++) {
            if ((participantBitmap >> i) & 1 == 0) continue;
            if (!started) {
                agg = pubkeys[i];
                started = true;
            } else {
                agg = BLS12381.g1Add(agg, pubkeys[i]);
            }
        }
    }

    /// @dev Deterministically derives an Fp2 element from
    ///      (chainId, blockNumber, stateRoot) and maps it to a G2 point via
    ///      the SWU precompile. This is a SIMPLIFIED message-to-curve step
    ///      (keccak256 directly as the Fp2 coordinates) rather than full
    ///      RFC9380 `expand_message_xmd` + `hash_to_field` — a deliberate
    ///      scope reduction (see bls-validators/README.md): the resulting
    ///      map is still deterministic, preimage-resistant, and uses the
    ///      SAME real SWU curve-mapping precompile as the standard, so
    ///      "forge a signature without the private key" is still as hard as
    ///      breaking BLS12-381 — just not bit-compatible with the official
    ///      Ethereum consensus hash-to-curve suite.
    function _hashToG2(uint256 chainId, uint256 blockNumber, uint256 stateRoot) internal view returns (bytes memory) {
        uint256 u0 = uint256(keccak256(abi.encode("BLS_MSG_U0", chainId, blockNumber, stateRoot)));
        uint256 u1 = uint256(keccak256(abi.encode("BLS_MSG_U1", chainId, blockNumber, stateRoot)));
        bytes memory fp2 = abi.encodePacked(BLS12381.encodeFp(u0), BLS12381.encodeFp(u1));
        return BLS12381.mapFp2ToG2(fp2);
    }

    function _popcount(uint256 x) internal pure returns (uint256 count) {
        while (x != 0) {
            count += x & 1;
            x >>= 1;
        }
    }
}
