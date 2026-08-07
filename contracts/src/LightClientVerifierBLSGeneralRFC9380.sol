// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BLS12381} from "./BLS12381.sol";
import {RFC9380} from "./RFC9380.sol";

/// @title LightClientVerifierBLSGeneralRFC9380
/// @notice Milestone 5 (see PLAN.md): identical to
///         `LightClientVerifierBLSGeneral.sol` (same registration flow,
///         same `bytes`-bitmap/arbitrary-N quorum mechanics — see that
///         contract's doc comment for those design notes, not repeated
///         here) EXCEPT `_hashToG2` now uses `RFC9380.hashToCurveG2` with
///         Ethereum's real ciphersuite DST
///         (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`) instead of the
///         simplified keccak-based curve mapping both
///         `LightClientVerifierBLS.sol` and `LightClientVerifierBLSGeneral.sol`
///         use.
///
///         A SEPARATE contract, not a modification of
///         `LightClientVerifierBLSGeneral.sol` — changing that contract's
///         message-to-curve in place would be a breaking change to
///         something already tested/relied on (a signature valid under the
///         old scheme silently stops verifying under the new one, and vice
///         versa; the two schemes are NOT interchangeable, see RFC9380.sol's
///         header comment for why the old one existed at all). This
///         contract is what `updateState()` looks like once wired to the
///         real primitive proven correct in `RFC9380.t.sol` and
///         `LightClientVerifierBLSReal.t.sol` (which verified an actual
///         Ethereum mainnet signature via `RFC9380`/`BLS12381` directly,
///         not through any `updateState()` call) — see
///         `contracts/test/LightClientVerifierBLSGeneralRFC9380.t.sol`.
///
///         The MESSAGE itself is still this protocol's own
///         `(chainId, blockNumber, stateRoot)` tuple, NOT Ethereum's SSZ
///         `signing_root` over a `BeaconBlockHeader` — those are different
///         things Milestone 5 solved separately. Real Ethereum sync
///         committee signatures attest to Ethereum's OWN consensus state;
///         this contract's signatures attest to whatever
///         (chainId, blockNumber, stateRoot) this protocol's own relayer
///         asks a committee to sign (same protocol as
///         `LightClientVerifierBLS(General)`, see those contracts and
///         PLAN.md Milestone 3). What changed here is only HOW that message
///         gets hashed to a curve point — now the real, standard algorithm,
///         not a simplified one.
contract LightClientVerifierBLSGeneralRFC9380 {
    /// See LightClientVerifierBLSGeneral.deployer's doc comment.
    address public immutable deployer;

    bytes[] public pubkeys; // G1 points, EIP-2537 encoding, 128 bytes each
    bool public finalized;
    uint256 public numValidators;
    uint256 public threshold;

    bytes internal constant NEG_G1_GENERATOR =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

    // Real Ethereum consensus ciphersuite DST — see RFC9380.sol / BLS12381.sol.
    bytes internal constant POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    mapping(uint256 => uint256) public trustedStateRoot;
    mapping(uint256 => uint256) public trustedBlockNumber;

    event ValidatorsAdded(uint256 newTotal);
    event Finalized(uint256 numValidators, uint256 threshold);
    event StateRootUpdated(uint256 indexed chainId, uint256 blockNumber, uint256 stateRoot);

    error NotDeployer();
    error AlreadyFinalized();
    error NotFinalized();
    error NoValidators();
    error InvalidPubkeyLength();
    error BitmapLengthMismatch();
    error PaddingBitsMustBeZero();
    error StaleBlockNumber();
    error InsufficientQuorum();
    error InvalidAggregateSignature();
    error InvalidSignatureLength();

    modifier onlyDeployer() {
        if (msg.sender != deployer) revert NotDeployer();
        _;
    }

    constructor() {
        deployer = msg.sender;
    }

    /// @notice See LightClientVerifierBLSGeneral.addValidators's doc
    ///         comment — same batching requirement, unrelated to the
    ///         message-to-curve change.
    function addValidators(bytes[] calldata newPubkeys) external onlyDeployer {
        if (finalized) revert AlreadyFinalized();
        for (uint256 i = 0; i < newPubkeys.length; i++) {
            if (newPubkeys[i].length != 128) revert InvalidPubkeyLength();
            pubkeys.push(newPubkeys[i]);
        }
        emit ValidatorsAdded(pubkeys.length);
    }

    function finalize() external onlyDeployer {
        if (finalized) revert AlreadyFinalized();
        if (pubkeys.length == 0) revert NoValidators();
        numValidators = pubkeys.length;
        threshold = (numValidators * 2 + 2) / 3; // ceil(2n/3)
        finalized = true;
        emit Finalized(numValidators, threshold);
    }

    /// @param participantBitmap Same `Bitvector[numValidators]` shape as
    ///        `LightClientVerifierBLSGeneral.updateState`.
    /// @param aggSig Sum of participating validators' individual signatures
    ///        over `RFC9380.hashToCurveG2(abi.encodePacked(chainId,
    ///        blockNumber, stateRoot), POP_DST)` — see
    ///        `bls-validators/sign_general_rfc9380.ts`.
    function updateState(
        uint256 chainId,
        uint256 blockNumber,
        uint256 stateRoot,
        bytes calldata participantBitmap,
        bytes calldata aggSig
    ) external {
        if (!finalized) revert NotFinalized();
        if (participantBitmap.length != (numValidators + 7) / 8) revert BitmapLengthMismatch();
        if (blockNumber <= trustedBlockNumber[chainId]) revert StaleBlockNumber();
        _checkPaddingBitsZero(participantBitmap);
        if (_popcount(participantBitmap) < threshold) revert InsufficientQuorum();
        if (aggSig.length != 256) revert InvalidSignatureLength();

        bytes memory aggPubkey = _aggregatePubkeys(participantBitmap);
        bytes memory messagePoint = RFC9380.hashToCurveG2(abi.encodePacked(chainId, blockNumber, stateRoot), POP_DST);

        bytes memory pairingInput = abi.encodePacked(aggPubkey, messagePoint, NEG_G1_GENERATOR, aggSig);
        if (!BLS12381.pairingCheck(pairingInput)) revert InvalidAggregateSignature();

        trustedStateRoot[chainId] = stateRoot;
        trustedBlockNumber[chainId] = blockNumber;

        emit StateRootUpdated(chainId, blockNumber, stateRoot);
    }

    function _aggregatePubkeys(bytes calldata participantBitmap) internal view returns (bytes memory agg) {
        bool started = false;
        for (uint256 i = 0; i < numValidators; i++) {
            if (!_bitSet(participantBitmap, i)) continue;
            if (!started) {
                agg = pubkeys[i];
                started = true;
            } else {
                agg = BLS12381.g1Add(agg, pubkeys[i]);
            }
        }
    }

    function _bitSet(bytes calldata bitmap, uint256 i) internal pure returns (bool) {
        return (uint8(bitmap[i >> 3]) >> (i & 7)) & 1 == 1;
    }

    /// @dev See LightClientVerifierBLSGeneral.sol's identically-named
    ///      function for why this must be bounded to `[0, numValidators)`
    ///      rather than counting every bit in the byte array — security
    ///      review finding, fixed here too (same bug, copied contract).
    function _popcount(bytes calldata bitmap) internal view returns (uint256 count) {
        for (uint256 i = 0; i < numValidators; i++) {
            if (_bitSet(bitmap, i)) count++;
        }
    }

    /// @dev See LightClientVerifierBLSGeneral.sol's identically-named
    ///      function.
    function _checkPaddingBitsZero(bytes calldata bitmap) internal view {
        uint256 totalBits = bitmap.length * 8;
        for (uint256 i = numValidators; i < totalBits; i++) {
            if (_bitSet(bitmap, i)) revert PaddingBitsMustBeZero();
        }
    }
}
