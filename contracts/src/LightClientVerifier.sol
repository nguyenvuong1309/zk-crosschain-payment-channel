// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Interface of the snarkjs-generated Groth16 verifier for
///         circuits/circuits/consensus_proof.circom. Public signal layout
///         (no circuit `output`s declared, so nothing is prepended — see
///         the circuit's doc comment):
///           [0]    chainId
///           [1]    blockNumber
///           [2]    stateRoot
///           [3..7] validatorPubKeyX[0..4]
///           [8..12] validatorPubKeyY[0..4]
interface IConsensusVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[13] calldata _pubSignals
    ) external view returns (bool);
}

/// @title LightClientVerifier
/// @notice Milestone 3's toy cross-chain "light client". Accepts a
///         consensus_proof.circom proof that at least `THRESHOLD` of this
///         contract's hardcoded `NUM_VALIDATORS` demo validators
///         (see docs/threat-model.md #6 — NOT a real consensus committee,
///         do not use to secure real value) attested to a
///         (chainId, blockNumber, stateRoot) triple, and stores the latest
///         attested stateRoot per source chain.
///
///         Any contract on THIS chain (see
///         PaymentChannel.closeWithRemoteAttestation) can then trust
///         `trustedStateRoot[chainId]` without trusting whoever relayed the
///         proof — a malicious/crashed relayer can delay or withhold
///         attestations (liveness risk) but cannot forge one, since the
///         proof cryptographically requires a real quorum of validator
///         signatures (safety holds, see docs/threat-model.md #7).
///
///         `stateRoot` is deliberately opaque to this contract — it does NOT
///         verify a real block header or Merkle-Patricia-trie inclusion
///         proof (real-Ethereum-light-client complexity, out of scope for
///         this demo — see PLAN.md Milestone 4). It's whatever value the
///         validator committee was asked to attest to (e.g. a channel's
///         final-state hash from PaymentChannel.sol on the source chain).
contract LightClientVerifier {
    IConsensusVerifier public immutable consensusVerifier;

    uint256 public constant NUM_VALIDATORS = 5;
    uint256 public constant THRESHOLD = 3;

    // The demo committee's public keys (circuits/input_gen/build_consensus_proof_input.js's
    // DEMO_VALIDATOR_PRIV_KEYS) — hardcoded so a proof can't smuggle in an
    // attacker-chosen "committee" that happens to satisfy the circuit's own
    // (self-consistent but otherwise unconstrained) quorum check.
    uint256 internal constant VALIDATOR_X_0 =
        21246438685519020325909427042851760438517789672650587758045368771856606251977;
    uint256 internal constant VALIDATOR_X_1 =
        17989828173199788198515330908044542986707065169673686905037405048349118572501;
    uint256 internal constant VALIDATOR_X_2 =
        6792796706312533171496143877377482156730541513184164084941301707682079080689;
    uint256 internal constant VALIDATOR_X_3 =
        7497374464861137184037981613537692868861134298803862847037479277114870475046;
    uint256 internal constant VALIDATOR_X_4 =
        12365000354977448349146557652237367341860215530550891410559730228320666707339;

    uint256 internal constant VALIDATOR_Y_0 =
        21757912420971379721172534150676790146484352047023251811005756971811108432764;
    uint256 internal constant VALIDATOR_Y_1 =
        5347085815635334027628529991145958795773335864739033871168351822057471290801;
    uint256 internal constant VALIDATOR_Y_2 =
        2674306955426078087016246293517136394933518656170578475876581817156998622208;
    uint256 internal constant VALIDATOR_Y_3 =
        7535159088071458283769393973861762513693647629357217726468953113823810968134;
    uint256 internal constant VALIDATOR_Y_4 =
        780711816540583673934192943661512197357117218017765651354867965984941584560;

    mapping(uint256 => uint256) public trustedStateRoot; // chainId => latest attested stateRoot
    mapping(uint256 => uint256) public trustedBlockNumber; // chainId => latest attested blockNumber

    event StateRootUpdated(uint256 indexed chainId, uint256 blockNumber, uint256 stateRoot);

    error InvalidConsensusProof();
    error StaleBlockNumber();
    error UnknownValidatorCommittee();

    constructor(IConsensusVerifier _consensusVerifier) {
        consensusVerifier = _consensusVerifier;
    }

    /// @notice Submits a consensus proof, updating `trustedStateRoot[chainId]`
    ///         if the proof verifies, the committee matches, and `blockNumber`
    ///         is newer than whatever was last accepted for this chainId
    ///         (monotonicity — otherwise a relayer could replay/rewind an
    ///         older, still-validly-signed attestation).
    function updateState(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[13] calldata pubSignals
    ) external {
        uint256 chainId = pubSignals[0];
        uint256 blockNumber = pubSignals[1];
        uint256 stateRoot = pubSignals[2];

        if (blockNumber <= trustedBlockNumber[chainId]) revert StaleBlockNumber();
        _checkCommittee(pubSignals);
        if (!consensusVerifier.verifyProof(a, b, c, pubSignals)) revert InvalidConsensusProof();

        trustedStateRoot[chainId] = stateRoot;
        trustedBlockNumber[chainId] = blockNumber;

        emit StateRootUpdated(chainId, blockNumber, stateRoot);
    }

    function _checkCommittee(uint256[13] calldata pubSignals) internal pure {
        if (
            pubSignals[3] != VALIDATOR_X_0 || pubSignals[4] != VALIDATOR_X_1 || pubSignals[5] != VALIDATOR_X_2
                || pubSignals[6] != VALIDATOR_X_3 || pubSignals[7] != VALIDATOR_X_4 || pubSignals[8] != VALIDATOR_Y_0
                || pubSignals[9] != VALIDATOR_Y_1 || pubSignals[10] != VALIDATOR_Y_2 || pubSignals[11] != VALIDATOR_Y_3
                || pubSignals[12] != VALIDATOR_Y_4
        ) revert UnknownValidatorCommittee();
    }
}
