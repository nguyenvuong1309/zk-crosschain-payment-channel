// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BLS12381} from "./BLS12381.sol";

/// @title LightClientVerifierBLSGeneral
/// @notice Milestone 5 step 3 (see PLAN.md): generalizes
///         `LightClientVerifierBLS.sol`'s hardcoded 5-key/3-of-5 demo
///         committee to an ARBITRARY committee size and a real 2/3
///         supermajority quorum — the size/threshold Ethereum's actual
///         512-validator sync committee uses (per the Altair light client
///         spec: an update is accepted iff `participation * 3 >=
///         numValidators * 2`).
///
///         Two mechanical problems the fixed-5 version never had to solve,
///         both real and worth stating plainly (see PLAN.md Milestone 5):
///
///         1. `participantBitmap` can no longer be a `uint256` — 512
///            validators need 512 bits. Now `bytes calldata`, encoded as an
///            SSZ `Bitvector[N]` would be (bit `i` at byte `i/8`, bit `i%8`,
///            LSB first) — the SAME convention
///            `bls-validators/sync_committee_probe.ts` already decodes from
///            REAL Ethereum `sync_committee_bits`, so this contract's
///            bitmap format is forward-compatible with real data once a
///            later Milestone 5 step wires that in.
///
///         2. Committee pubkeys can no longer be hardcoded `bytes constant`
///            values baked into the contract's bytecode — 512 keys x 128
///            bytes (EIP-2537 G1 encoding) = 65,536 bytes, which alone
///            blows past EIP-170's 24,576-byte deployed-code size limit
///            several times over, before counting the rest of the
///            contract's logic. Pubkeys are registered into STORAGE
///            instead, via `addValidators()` called in batches across
///            MULTIPLE transactions (see its doc comment for why a single
///            constructor call doesn't work either — the real committee
///            wouldn't fit in one block's gas limit).
///
///         Still uses the SAME simplified (non-RFC9380, non-SSZ-signing-root)
///         message-to-curve as `LightClientVerifierBLS.sol` — see that
///         contract's `_hashToG2` doc comment. Swapping in Ethereum's real
///         signing_root computation is a SEPARATE, not-yet-done Milestone 5
///         step (see PLAN.md's SSZ merkle proof item) — this contract only
///         generalizes committee size/quorum mechanics, deliberately scoped
///         apart from that.
contract LightClientVerifierBLSGeneral {
    /// @dev Only used during the registration phase (`addValidators`,
    ///      `finalize`) — irrelevant once `finalized`, `updateState` has no
    ///      access control of its own (same as `LightClientVerifierBLS`:
    ///      the aggregate signature IS the authorization).
    address public immutable deployer;

    bytes[] public pubkeys; // G1 points, EIP-2537 encoding, 128 bytes each
    bool public finalized;
    uint256 public numValidators;
    uint256 public threshold;

    // -G1 (negated generator), same constant regardless of committee size —
    // see LightClientVerifierBLS.sol for the pairing-check identity this
    // makes possible.
    bytes internal constant NEG_G1_GENERATOR =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

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

    /// @notice Registers a batch of committee pubkeys. Callable multiple
    ///         times (e.g. 32-64 validators per call) so the full 512-key
    ///         committee never needs to fit in a single transaction's gas
    ///         limit — SSTORE for a 128-byte `bytes` array element costs
    ///         ~5 storage slots (cold-write ~22,100 gas/slot), so 512 keys
    ///         in ONE transaction would need >55M gas, well over any real
    ///         block's gas limit. Batching is not an optimization here, it's
    ///         a hard requirement — see PLAN.md Milestone 5's gas
    ///         measurement item for the actual numbers this produces.
    function addValidators(bytes[] calldata newPubkeys) external onlyDeployer {
        if (finalized) revert AlreadyFinalized();
        for (uint256 i = 0; i < newPubkeys.length; i++) {
            if (newPubkeys[i].length != 128) revert InvalidPubkeyLength();
            pubkeys.push(newPubkeys[i]);
        }
        emit ValidatorsAdded(pubkeys.length);
    }

    /// @notice Locks the committee and computes the quorum threshold as
    ///         `ceil(2 * numValidators / 3)` — the same supermajority rule
    ///         Ethereum's Altair light client spec uses
    ///         (`sum(sync_committee_bits) * 3 >= len(sync_committee_bits) * 2`).
    ///         No more validators can be added after this.
    function finalize() external onlyDeployer {
        if (finalized) revert AlreadyFinalized();
        if (pubkeys.length == 0) revert NoValidators();
        numValidators = pubkeys.length;
        threshold = (numValidators * 2 + 2) / 3; // ceil(2n/3) via integer division
        finalized = true;
        emit Finalized(numValidators, threshold);
    }

    /// @param participantBitmap `Bitvector[numValidators]`-shaped, LSB
    ///        first: bit `i` (validator `i` signed) lives at byte `i/8`,
    ///        bit `i%8`. Length must be exactly `ceil(numValidators/8)`
    ///        bytes.
    /// @param aggSig Sum (G2 point addition) of every participating
    ///        validator's individual signature over the same message point
    ///        — see `bls-validators/sign_general.ts`.
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
        if (_popcount(participantBitmap) < threshold) revert InsufficientQuorum();
        if (aggSig.length != 256) revert InvalidSignatureLength();

        bytes memory aggPubkey = _aggregatePubkeys(participantBitmap);
        bytes memory messagePoint = _hashToG2(chainId, blockNumber, stateRoot);

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

    /// @dev Same simplified message-to-curve as LightClientVerifierBLS.sol
    ///      — see that contract's identically-named function for the full
    ///      caveat (not RFC9380/SSZ-signing-root compatible yet).
    function _hashToG2(uint256 chainId, uint256 blockNumber, uint256 stateRoot) internal view returns (bytes memory) {
        uint256 u0 = uint256(keccak256(abi.encode("BLS_MSG_U0", chainId, blockNumber, stateRoot)));
        uint256 u1 = uint256(keccak256(abi.encode("BLS_MSG_U1", chainId, blockNumber, stateRoot)));
        bytes memory fp2 = abi.encodePacked(BLS12381.encodeFp(u0), BLS12381.encodeFp(u1));
        return BLS12381.mapFp2ToG2(fp2);
    }

    function _bitSet(bytes calldata bitmap, uint256 i) internal pure returns (bool) {
        return (uint8(bitmap[i >> 3]) >> (i & 7)) & 1 == 1;
    }

    function _popcount(bytes calldata bitmap) internal pure returns (uint256 count) {
        for (uint256 i = 0; i < bitmap.length; i++) {
            uint8 b = uint8(bitmap[i]);
            while (b != 0) {
                count += b & 1;
                b >>= 1;
            }
        }
    }
}
