// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {BabyJubJub} from "./BabyJubJub.sol";
import {IPoseidonT4, PoseidonT4Deployer} from "./PoseidonT4.sol";

/// @notice Interface of the snarkjs-generated Groth16 verifier for
///         circuits/circuits/channel_state.circom. Public signal layout
///         (circom always emits outputs first, then public inputs in
///         `component main {public [...]}` declaration order):
///           [0]  outNonce            [6]  pubKeyBx
///           [1]  startCommitment     [7]  pubKeyBy
///           [2]  endCommitment       [8]  contractAddress
///           [3]  channelId           [9]  chainId
///           [4]  pubKeyAx            [10] startNonce
///           [5]  pubKeyAy
/// `contractAddress`/`chainId` are the domain separator baked into the
/// signed message inside the circuit — see channel_state.circom.
/// `startCommitment`/`endCommitment` are both `Poseidon(balanceA, balanceB,
/// blinding)` — the SAME 3-input formula at both ends of the chain on
/// purpose (see channel_state.circom's doc comment on "Chaining"): balances
/// are never revealed by a proof, only committed to, and a later proof's
/// `startCommitment`/`startNonce` must match an earlier proof's
/// `endCommitment`/`outNonce` (or the channel's genesis deposits, for the
/// first proof in a chain) — see `_verifyChannelProof`.
interface IChannelStateVerifier {
    function verifyProof(
        uint256[2] calldata _pA,
        uint256[2][2] calldata _pB,
        uint256[2] calldata _pC,
        uint256[11] calldata _pubSignals
    ) external view returns (bool);
}

/// @notice Minimal view into LightClientVerifier.sol (Milestone 3) — the
///         latest validator-attested `stateRoot` this chain trusts for a
///         given remote `chainId`. See `closeWithRemoteAttestation`.
interface ILightClientVerifier {
    function trustedStateRoot(uint256 chainId) external view returns (uint256);
}

/// @title PaymentChannel
/// @notice Bidirectional, single-chain, 2-party payment channel.
///
/// Lifecycle:
///   1. `open()`/`join()` — both parties lock funds AND register the EdDSA
///                       public key they'll use to sign off-chain updates
///                       (separate from their ECDSA on-chain address — see
///                       PLAN.md section 2 for why). Channel becomes ACTIVE.
///                       Registering a non-zero key requires proving
///                       ownership of it via a Schnorr signature over the
///                       same Baby Jubjub keypair (see `_verifyKeyOwnership`)
///                       — otherwise anyone could register someone else's
///                       public EdDSA key against their own channel (see
///                       docs/threat-model.md assumption #5).
///   2. off-chain     — parties exchange EdDSA-signed `ChannelState` updates
///                       (nonce strictly increasing). No on-chain tx per
///                       update.
///   3a. `closeCooperative()` — either party submits a state signed (ECDSA,
///                       raw) by BOTH parties; settles immediately, no
///                       challenge period.
///   3b. `closeUnilateral()`  — one party submits their latest known state
///                       (ECDSA-signed by both), starts a challenge window.
///   3c. `closeWithProof()`   — one party submits a ZK proof that a valid,
///                       EdDSA-signed chain of off-chain updates leads to a
///                       claimed final state, instead of raw signatures.
///                       The contract never sees the off-chain history, only
///                       a succinct proof of it (Milestone 2, PLAN.md).
///                       Also starts a challenge window.
///   4.  `challenge()` / `challengeWithProof()` — the other party can submit
///                       a NEWER (higher-nonce) state, signed or proven,
///                       during the window to override a stale close.
///   5.  `withdraw()`  — after the challenge window expires, funds settle
///                       per the final undisputed state.
///
/// The raw-signature path (3a/3b) and the ZK-proof path (3c) are kept side
/// by side deliberately: they settle the exact same channel and are useful
/// to compare directly (gas cost, calldata size) as off-chain history grows.
contract PaymentChannel {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    enum Status {
        UNINITIALIZED,
        ACTIVE,
        CHALLENGE_PERIOD,
        CLOSED
    }

    /// @notice Off-chain-signed snapshot of channel balances.
    struct ChannelState {
        uint256 channelId;
        uint256 nonce; // strictly increasing per update
        uint256 balanceA; // partyA's balance at this state
        uint256 balanceB; // partyB's balance at this state
    }

    struct Channel {
        address partyA;
        address partyB;
        uint256 depositA;
        uint256 depositB;
        Status status;
        uint256 nonce; // nonce of the currently-posted (possibly disputed) state
        uint256 balanceA;
        uint256 balanceB;
        uint256 challengeExpiry;
        // EdDSA (Baby Jubjub) public keys registered at open/join time, used
        // to verify off-chain updates inside channel_state.circom. Separate
        // from partyA/partyB's ECDSA addresses above — see contract-level
        // docs for why.
        uint256 pubKeyAx;
        uint256 pubKeyAy;
        uint256 pubKeyBx;
        uint256 pubKeyBy;
        // Set by closeWithProof/challengeWithProof instead of balanceA/B
        // (see IChannelStateVerifier's doc comment on balanceCommitment):
        // the ZK-proof path never reveals the final split on-chain, only a
        // Poseidon commitment to it. `balancesCommitted` gates withdraw() —
        // true means balanceA/B below are stale and withdrawWithOpening()
        // must be used instead, which checks the opening against this
        // commitment before paying out. A later raw-signature close/challenge
        // (closeCooperative/closeUnilateral/challenge) clears this flag,
        // since those reveal balanceA/B directly.
        uint256 balanceCommitment;
        bool balancesCommitted;
    }

    uint256 public constant CHALLENGE_PERIOD = 1 days;

    IChannelStateVerifier public immutable channelStateVerifier;
    // address(0) means "no light client configured" — closeWithRemoteAttestation
    // is disabled, everything else is unaffected (see its own zero-address check).
    ILightClientVerifier public immutable lightClientVerifier;
    // Deployed once in the constructor from PoseidonT4Bytecode (see
    // PoseidonT4.sol) — used only to open a balanceCommitment at withdraw
    // time, matching channel_state.circom's Poseidon(3).
    IPoseidonT4 public immutable poseidonT4;

    uint256 public nextChannelId;
    // Not `public`: with `balanceCommitment`/`balancesCommitted` added, the
    // auto-generated flat-tuple getter for this struct trips solc's
    // "stack too deep" limit even under via-ir (too many return values
    // encoded at once). `getChannel` below returns the same data as a
    // single struct value instead, which encodes fine.
    mapping(uint256 => Channel) internal channels;

    /// @notice Read a channel's full state. Replaces the auto-generated
    ///         public-mapping getter (see `channels`' doc comment).
    function getChannel(uint256 channelId) external view returns (Channel memory) {
        return channels[channelId];
    }

    /// @notice Funds that couldn't be pushed to their recipient during a
    ///         payout (e.g. recipient is a contract that reverts on
    ///         receiving ETH). Claimable any time via `claim()`. This exists
    ///         so that ONE uncooperative/broken party can never block the
    ///         OTHER party's funds from settling — see `_payout`.
    mapping(address => uint256) public pendingWithdrawals;

    event ChannelOpened(
        uint256 indexed channelId, address indexed partyA, address indexed partyB, uint256 depositA, uint256 depositB
    );
    event ChannelCancelled(uint256 indexed channelId, uint256 refundedToPartyA);
    event ChannelClosedCooperatively(uint256 indexed channelId, uint256 nonce, uint256 balanceA, uint256 balanceB);
    event ChannelClosedUnilaterally(uint256 indexed channelId, uint256 nonce, uint256 challengeExpiry);
    event ChannelChallenged(uint256 indexed channelId, uint256 newNonce, address indexed challenger);
    event ChannelWithdrawn(uint256 indexed channelId, uint256 balanceA, uint256 balanceB);
    event PayoutCredited(address indexed to, uint256 amount);
    event Claimed(address indexed to, uint256 amount);

    error InvalidParty();
    error WrongStatus(Status expected, Status actual);
    error InvalidSignatures();
    error StaleNonce();
    error DepositMismatch();
    error ChannelIdMismatch();
    error ChallengeWindowOpen();
    error ChallengeWindowClosed();
    error ZeroAddress();
    error InvalidProof();
    error PublicKeyMismatch();
    error InvalidChainAnchor();
    error NothingToClaim();
    error ClaimTransferFailed();
    error DomainMismatch();
    error InvalidKeyOwnershipProof();
    error LightClientNotConfigured();
    error UntrustedRemoteState();
    error BalancesNotYetRevealed();
    error CommitmentMismatch();

    modifier onlyParty(uint256 channelId) {
        Channel storage ch = channels[channelId];
        if (msg.sender != ch.partyA && msg.sender != ch.partyB) revert InvalidParty();
        _;
    }

    constructor(IChannelStateVerifier _channelStateVerifier, ILightClientVerifier _lightClientVerifier) {
        channelStateVerifier = _channelStateVerifier;
        lightClientVerifier = _lightClientVerifier;
        // Deployed fresh per PaymentChannel instance rather than passed in:
        // the bytecode is fixed/parameterless (see PoseidonT4.sol), so
        // there's nothing a caller could usefully configure, and this keeps
        // deployment scripts/tests to a single `new PaymentChannel(...)`.
        poseidonT4 = IPoseidonT4(new PoseidonT4Deployer().deploy());
    }

    /// @notice Open a new channel. Caller is partyA and must send depositA as msg.value
    ///         together with depositB is pulled conceptually off-chain in this simple
    ///         demo (partyB funds by calling `join`). `pubKeyAx/Ay` is partyA's EdDSA
    ///         public key, used to verify off-chain updates when closing via ZK proof.
    ///         `sigR8x/R8y/sigS` prove partyA actually holds the matching private key
    ///         (see `_verifyKeyOwnership`); pass `pubKeyAx == pubKeyAy == 0` (and zero
    ///         signature) for a channel that will only ever use the raw-signature close
    ///         path and never registers an EdDSA identity.
    function open(
        address partyB,
        uint256 depositA,
        uint256 pubKeyAx,
        uint256 pubKeyAy,
        uint256 sigR8x,
        uint256 sigR8y,
        uint256 sigS
    ) external payable returns (uint256 channelId) {
        if (partyB == address(0)) revert ZeroAddress();
        if (msg.value != depositA) revert DepositMismatch();

        channelId = nextChannelId++;
        _verifyKeyOwnership(channelId, msg.sender, pubKeyAx, pubKeyAy, sigR8x, sigR8y, sigS);

        Channel storage ch = channels[channelId];
        ch.partyA = msg.sender;
        ch.partyB = partyB;
        ch.depositA = depositA;
        ch.status = Status.UNINITIALIZED; // becomes ACTIVE once partyB joins
        ch.balanceA = depositA;
        ch.pubKeyAx = pubKeyAx;
        ch.pubKeyAy = pubKeyAy;

        emit ChannelOpened(channelId, msg.sender, partyB, depositA, 0);
    }

    /// @notice PartyB joins and funds their side of an UNINITIALIZED channel,
    ///         registering their own EdDSA public key (see `open()`'s doc comment
    ///         on `sigR8x/R8y/sigS` and the zero-key exemption).
    function join(uint256 channelId, uint256 pubKeyBx, uint256 pubKeyBy, uint256 sigR8x, uint256 sigR8y, uint256 sigS)
        external
        payable
    {
        Channel storage ch = channels[channelId];
        if (msg.sender != ch.partyB) revert InvalidParty();
        if (ch.status != Status.UNINITIALIZED) revert WrongStatus(Status.UNINITIALIZED, ch.status);
        _verifyKeyOwnership(channelId, msg.sender, pubKeyBx, pubKeyBy, sigR8x, sigR8y, sigS);

        ch.depositB = msg.value;
        ch.balanceB = msg.value;
        ch.status = Status.ACTIVE;
        ch.pubKeyBx = pubKeyBx;
        ch.pubKeyBy = pubKeyBy;

        emit ChannelOpened(channelId, ch.partyA, ch.partyB, ch.depositA, ch.depositB);
    }

    /// @notice PartyA reclaims their deposit if partyB never joins. Without
    ///         this, an UNINITIALIZED channel has no way to ever release
    ///         partyA's funds — they'd be locked forever if partyB simply
    ///         never calls `join`.
    function cancelUnjoined(uint256 channelId) external {
        Channel storage ch = channels[channelId];
        if (msg.sender != ch.partyA) revert InvalidParty();
        if (ch.status != Status.UNINITIALIZED) revert WrongStatus(Status.UNINITIALIZED, ch.status);

        uint256 refund = ch.depositA;
        ch.balanceA = 0;
        ch.depositA = 0;
        ch.status = Status.CLOSED;

        emit ChannelCancelled(channelId, refund);

        _creditOrSend(ch.partyA, refund);
    }

    /// @notice Close the channel immediately using a state signed by BOTH parties.
    ///         No challenge period needed since both parties agree.
    function closeCooperative(ChannelState calldata state, bytes calldata sigA, bytes calldata sigB)
        external
        onlyParty(state.channelId)
    {
        Channel storage ch = channels[state.channelId];
        if (ch.status != Status.ACTIVE && ch.status != Status.CHALLENGE_PERIOD) {
            revert WrongStatus(Status.ACTIVE, ch.status);
        }
        _verifyBothSignatures(ch, state.channelId, state, sigA, sigB);
        _checkConservation(ch, state);

        ch.balanceA = state.balanceA;
        ch.balanceB = state.balanceB;
        ch.nonce = state.nonce;
        ch.balancesCommitted = false;
        ch.status = Status.CLOSED;

        _payout(ch);

        emit ChannelClosedCooperatively(state.channelId, state.nonce, state.balanceA, state.balanceB);
    }

    /// @notice Start unilateral close with the latest state either party has,
    ///         signed by both. Opens a challenge window for the counterparty
    ///         to override with a newer state, in case this one is stale.
    function closeUnilateral(ChannelState calldata state, bytes calldata sigA, bytes calldata sigB)
        external
        onlyParty(state.channelId)
    {
        Channel storage ch = channels[state.channelId];
        if (ch.status != Status.ACTIVE) revert WrongStatus(Status.ACTIVE, ch.status);
        _verifyBothSignatures(ch, state.channelId, state, sigA, sigB);
        _checkConservation(ch, state);

        ch.balanceA = state.balanceA;
        ch.balanceB = state.balanceB;
        ch.nonce = state.nonce;
        ch.balancesCommitted = false;
        ch.status = Status.CHALLENGE_PERIOD;
        ch.challengeExpiry = block.timestamp + CHALLENGE_PERIOD;

        emit ChannelClosedUnilaterally(state.channelId, state.nonce, ch.challengeExpiry);
    }

    /// @notice During the challenge window, submit a newer (higher-nonce) signed
    ///         state to override a stale unilateral close attempt.
    /// @dev Deliberately NOT `onlyParty` — unlike the close/open functions,
    ///      authorization here comes entirely from `sigA`/`sigB` (both
    ///      parties' signatures over `state`, checked below), not from
    ///      `msg.sender`. This is what lets a third-party watchtower submit
    ///      a rescue challenge on a party's behalf while that party is
    ///      offline (Milestone 4, see docs/threat-model.md #2 and
    ///      `watchtower/`) — the watchtower never needs either party's
    ///      private key, only a copy of the latest co-signed state.
    function challenge(ChannelState calldata state, bytes calldata sigA, bytes calldata sigB) external {
        Channel storage ch = channels[state.channelId];
        if (ch.status != Status.CHALLENGE_PERIOD) revert WrongStatus(Status.CHALLENGE_PERIOD, ch.status);
        if (block.timestamp >= ch.challengeExpiry) revert ChallengeWindowClosed();
        if (state.nonce <= ch.nonce) revert StaleNonce();

        _verifyBothSignatures(ch, state.channelId, state, sigA, sigB);
        _checkConservation(ch, state);

        ch.balanceA = state.balanceA;
        ch.balanceB = state.balanceB;
        ch.nonce = state.nonce;
        ch.balancesCommitted = false;
        // extend the window so the other party has a fair chance to re-challenge
        ch.challengeExpiry = block.timestamp + CHALLENGE_PERIOD;

        emit ChannelChallenged(state.channelId, state.nonce, msg.sender);
    }

    /// @notice Start unilateral close using a ZK proof (channel_state.circom)
    ///         instead of raw signatures — the contract only ever sees this
    ///         single proof, never the off-chain update history it attests
    ///         to. Opens the same challenge window as `closeUnilateral`,
    ///         since a valid proof can still describe a STALE (but genuinely
    ///         signed) chain of updates — ZK correctness proves the chain is
    ///         internally consistent, not that it's the most recent one.
    function closeWithProof(
        uint256 channelId,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[11] calldata pubSignals
    ) external onlyParty(channelId) {
        Channel storage ch = channels[channelId];
        if (ch.status != Status.ACTIVE) revert WrongStatus(Status.ACTIVE, ch.status);

        (uint256 outNonce, uint256 balanceCommitment) = _verifyChannelProof(ch, channelId, a, b, c, pubSignals);
        if (outNonce < ch.nonce) revert StaleNonce();

        ch.balanceCommitment = balanceCommitment;
        ch.balancesCommitted = true;
        ch.nonce = outNonce;
        ch.status = Status.CHALLENGE_PERIOD;
        ch.challengeExpiry = block.timestamp + CHALLENGE_PERIOD;

        emit ChannelClosedUnilaterally(channelId, outNonce, ch.challengeExpiry);
    }

    /// @notice During the challenge window, submit a ZK proof of a NEWER
    ///         (higher-nonce) chain of updates to override a stale close —
    ///         the proof-based counterpart to `challenge()`.
    /// @dev Also deliberately NOT `onlyParty` — see `challenge()`'s doc
    ///      comment; authorization here comes from the ZK proof itself.
    function challengeWithProof(
        uint256 channelId,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[11] calldata pubSignals
    ) external {
        Channel storage ch = channels[channelId];
        if (ch.status != Status.CHALLENGE_PERIOD) revert WrongStatus(Status.CHALLENGE_PERIOD, ch.status);
        if (block.timestamp >= ch.challengeExpiry) revert ChallengeWindowClosed();

        (uint256 outNonce, uint256 balanceCommitment) = _verifyChannelProof(ch, channelId, a, b, c, pubSignals);
        if (outNonce <= ch.nonce) revert StaleNonce();

        ch.balanceCommitment = balanceCommitment;
        ch.balancesCommitted = true;
        ch.nonce = outNonce;
        // extend the window so the other party has a fair chance to re-challenge
        ch.challengeExpiry = block.timestamp + CHALLENGE_PERIOD;

        emit ChannelChallenged(channelId, outNonce, msg.sender);
    }

    /// @notice Settles this channel to the final state attested for the SAME
    ///         channelId on a DIFFERENT chain/deployment (`remoteContract`/
    ///         `remoteChainId`), via this chain's configured
    ///         LightClientVerifier — Milestone 3's "virtual channel"
    ///         cross-chain settle: a party who closed/settled their channel
    ///         on Chain A can have the exact same final balances recognized
    ///         on Chain B, without any real bridge/asset transfer (see
    ///         PLAN.md Milestone 3, "Nối L2 + L3").
    /// @dev The attested value is
    ///      `keccak256(remoteContract, remoteChainId, channelId, nonce, balanceA, balanceB) % BabyJubJub.Q`
    ///      — the SAME domain-separated hash formula as `hashState()`, just
    ///      evaluated with the REMOTE chain's domain instead of
    ///      `address(this)`/`block.chainid` (since that's what was actually
    ///      signed/attested there), reduced into the circuit's scalar field
    ///      since it's carried as a `stateRoot` public signal in
    ///      consensus_proof.circom. Starts the same challenge window as
    ///      `closeWithProof`/`closeUnilateral` — a remote attestation can
    ///      still describe a stale (but genuinely once-true) state.
    function closeWithRemoteAttestation(
        uint256 channelId,
        address remoteContract,
        uint256 remoteChainId,
        ChannelState calldata state
    ) external onlyParty(channelId) {
        if (address(lightClientVerifier) == address(0)) revert LightClientNotConfigured();
        Channel storage ch = channels[channelId];
        if (ch.status != Status.ACTIVE) revert WrongStatus(Status.ACTIVE, ch.status);
        if (state.channelId != channelId) revert ChannelIdMismatch();
        if (state.nonce < ch.nonce) revert StaleNonce();
        _checkConservation(ch, state);

        uint256 remoteStateHash = uint256(
            keccak256(
                abi.encode(remoteContract, remoteChainId, state.channelId, state.nonce, state.balanceA, state.balanceB)
            )
        ) % BabyJubJub.Q;
        if (remoteStateHash != lightClientVerifier.trustedStateRoot(remoteChainId)) revert UntrustedRemoteState();

        ch.balanceA = state.balanceA;
        ch.balanceB = state.balanceB;
        ch.nonce = state.nonce;
        ch.balancesCommitted = false;
        ch.status = Status.CHALLENGE_PERIOD;
        ch.challengeExpiry = block.timestamp + CHALLENGE_PERIOD;

        emit ChannelClosedUnilaterally(channelId, state.nonce, ch.challengeExpiry);
    }

    /// @notice After the challenge window expires undisputed, settle funds.
    /// @dev Reverts if the channel closed via `closeWithProof`/
    ///      `challengeWithProof` and was never subsequently overridden by a
    ///      raw-signature close/challenge — those only leave a
    ///      `balanceCommitment` on-chain (see Channel.balancesCommitted),
    ///      not the actual split. Use `withdrawWithOpening` in that case.
    function withdraw(uint256 channelId) external onlyParty(channelId) {
        Channel storage ch = channels[channelId];
        if (ch.status != Status.CHALLENGE_PERIOD) revert WrongStatus(Status.CHALLENGE_PERIOD, ch.status);
        if (block.timestamp < ch.challengeExpiry) revert ChallengeWindowOpen();
        if (ch.balancesCommitted) revert BalancesNotYetRevealed();

        ch.status = Status.CLOSED;
        _payout(ch);

        emit ChannelWithdrawn(channelId, ch.balanceA, ch.balanceB);
    }

    /// @notice Settles a channel that closed via `closeWithProof`/
    ///         `challengeWithProof` (see `balanceCommitment`/`balancesCommitted`
    ///         on `Channel`, and channel_state.circom's doc comment on why the
    ///         final split isn't revealed until now). The caller must supply
    ///         the exact `(balanceA, balanceB, blinding)` the proof committed
    ///         to; anyone who lost `blinding` cannot open the commitment and
    ///         the channel's funds become unwithdrawable — the same failure
    ///         mode as losing a private key, not a new one introduced here
    ///         (both parties independently know these values off-chain, same
    ///         as they'd know a raw-signature state).
    /// @dev `balanceA + balanceB == depositA + depositB` is re-checked here
    ///      even though channel_state.circom already enforces conservation
    ///      internally — defense in depth against a verifier-contract bug,
    ///      matching the pattern `_checkConservation` uses on the
    ///      raw-signature paths.
    function withdrawWithOpening(uint256 channelId, uint256 balanceA, uint256 balanceB, uint256 blinding)
        external
        onlyParty(channelId)
    {
        Channel storage ch = channels[channelId];
        if (ch.status != Status.CHALLENGE_PERIOD) revert WrongStatus(Status.CHALLENGE_PERIOD, ch.status);
        if (block.timestamp < ch.challengeExpiry) revert ChallengeWindowOpen();
        if (!ch.balancesCommitted) revert BalancesNotYetRevealed();
        if (balanceA + balanceB != ch.depositA + ch.depositB) revert DepositMismatch();

        uint256[3] memory opening = [balanceA, balanceB, blinding];
        if (poseidonT4.poseidon(opening) != ch.balanceCommitment) revert CommitmentMismatch();

        ch.balanceA = balanceA;
        ch.balanceB = balanceB;
        ch.balancesCommitted = false;
        ch.status = Status.CLOSED;
        _payout(ch);

        emit ChannelWithdrawn(channelId, balanceA, balanceB);
    }

    // ---------------------------------------------------------------------
    // internal helpers
    // ---------------------------------------------------------------------

    /// @notice Proves the caller registering `(pubKeyX, pubKeyY)` actually holds
    ///         the matching Baby Jubjub private key, closing the gap noted in
    ///         docs/threat-model.md assumption #5: previously any value could be
    ///         passed as a party's EdDSA public key, including someone else's —
    ///         letting an attacker register a victim's key against an attacker-
    ///         controlled channel (the key itself is public, e.g. visible in any
    ///         prior channel's calldata).
    /// @dev `(0, 0)` is an explicit exemption: a channel that only ever uses the
    ///      raw-signature close path (`closeCooperative`/`closeUnilateral`) never
    ///      needs an EdDSA identity at all (see `test/PaymentChannel.t.sol`,
    ///      `test/PaymentChannelSecurityFixes.t.sol`).
    ///
    ///      Verifies a plain Schnorr signature over the SAME Baby Jubjub curve/
    ///      keypair circomlib's EdDSA uses (so the proven key is exactly the one
    ///      later checked in `channel_state.circom`) — but with a keccak256
    ///      Fiat-Shamir challenge instead of circomlib's Poseidon one, since
    ///      Poseidon is cheap in-circuit but expensive as plain EVM opcodes.
    ///      This signature is NOT interchangeable with the EdDSA-Poseidon
    ///      signatures used inside the circuit; it only proves key ownership at
    ///      registration time. See `circuits/input_gen/eddsa_ownership.js` for
    ///      the off-chain signer. Domain-bound to `(address(this), block.chainid,
    ///      channelId, party)`, mirroring `hashState`'s domain separator, so a
    ///      registration proof for one channel/deployment can't be replayed for
    ///      another.
    function _verifyKeyOwnership(
        uint256 channelId,
        address party,
        uint256 pubKeyX,
        uint256 pubKeyY,
        uint256 sigR8x,
        uint256 sigR8y,
        uint256 sigS
    ) internal view {
        if (pubKeyX == 0 && pubKeyY == 0) return;
        if (!BabyJubJub.isOnCurve(pubKeyX, pubKeyY)) revert InvalidKeyOwnershipProof();
        if (sigS >= BabyJubJub.SUB_ORDER) revert InvalidKeyOwnershipProof();

        uint256 ownershipChallenge = uint256(
            keccak256(
                abi.encode(
                    "EDDSA_OWNERSHIP", address(this), block.chainid, channelId, party, pubKeyX, pubKeyY, sigR8x, sigR8y
                )
            )
        ) % BabyJubJub.SUB_ORDER;

        (uint256 lx, uint256 ly) = BabyJubJub.mulScalar(BabyJubJub.BASE8_X, BabyJubJub.BASE8_Y, sigS);
        (uint256 cAx, uint256 cAy) = BabyJubJub.mulScalar(pubKeyX, pubKeyY, ownershipChallenge);
        (uint256 rx, uint256 ry) = BabyJubJub.pointAdd(sigR8x, sigR8y, cAx, cAy);

        if (lx != rx || ly != ry) revert InvalidKeyOwnershipProof();
    }

    function _checkConservation(Channel storage ch, ChannelState calldata state) internal view {
        if (state.balanceA + state.balanceB != ch.depositA + ch.depositB) revert DepositMismatch();
    }

    function _verifyBothSignatures(
        Channel storage ch,
        uint256 channelId,
        ChannelState calldata state,
        bytes calldata sigA,
        bytes calldata sigB
    ) internal view {
        if (state.channelId != channelId) revert ChannelIdMismatch();
        if (state.nonce < ch.nonce) revert StaleNonce();

        bytes32 digest = hashState(state).toEthSignedMessageHash();
        if (digest.recover(sigA) != ch.partyA) revert InvalidSignatures();
        if (digest.recover(sigB) != ch.partyB) revert InvalidSignatures();
    }

    /// @notice Verifies a channel_state.circom proof against this channel's
    ///         registered identity/deposits/anchor state, and decodes its
    ///         public outputs. See `IChannelStateVerifier` for the public
    ///         signal layout.
    /// @dev Domain-bound: `contractAddress`/`chainId` are checked against
    ///      `address(this)`/`block.chainid`, mirroring `hashState`'s domain
    ///      separator on the raw-signature path — without this, a proof
    ///      valid for channelId N on one deployment would also verify for
    ///      channelId N on any other deployment with matching registered
    ///      EdDSA keys/deposits (e.g. this project's own Chain A / Chain B).
    ///      These fields are baked into the signed message INSIDE the
    ///      circuit (see channel_state.circom), not just carried as unchecked
    ///      public signals, so the binding is enforced cryptographically.
    ///
    ///      Chaining (see channel_state.circom's doc comment): exactly ONE
    ///      of two anchors is accepted, selected by `ch.balancesCommitted`:
    ///        - false (no proof has ever closed this channel yet — it's
    ///          still ACTIVE, or currently in CHALLENGE_PERIOD via the
    ///          raw-signature path only): the proof must be genesis-anchored
    ///          — `startNonce == 0` and `startCommitment ==
    ///          Poseidon(depositA, depositB, 0)`. `0` is a fixed, publicly
    ///          computable blinding for this one case (deposits are already
    ///          public since `open()`/`join()`), not a secret.
    ///        - true (a prior closeWithProof/challengeWithProof already ran
    ///          for this channel): the proof must CONTINUE from it —
    ///          `startNonce == ch.nonce` and `startCommitment ==
    ///          ch.balanceCommitment`, both already stored on-chain by that
    ///          prior proof. This is what lets a channel's full off-chain
    ///          history span arbitrarily many proofs, each only paying for
    ///          `steps` updates' worth of constraints, instead of a single
    ///          proof needing to grow with the channel's entire lifetime.
    function _verifyChannelProof(
        Channel storage ch,
        uint256 channelId,
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[11] calldata pubSignals
    ) internal view returns (uint256 outNonce, uint256 endCommitment) {
        if (pubSignals[3] != channelId) revert ChannelIdMismatch();
        if (pubSignals[4] != ch.pubKeyAx || pubSignals[5] != ch.pubKeyAy) revert PublicKeyMismatch();
        if (pubSignals[6] != ch.pubKeyBx || pubSignals[7] != ch.pubKeyBy) revert PublicKeyMismatch();
        if (pubSignals[8] != uint256(uint160(address(this)))) revert DomainMismatch();
        if (pubSignals[9] != block.chainid) revert DomainMismatch();

        uint256 startCommitment = pubSignals[1];
        uint256 startNonce = pubSignals[10];
        if (ch.balancesCommitted) {
            if (startNonce != ch.nonce || startCommitment != ch.balanceCommitment) revert InvalidChainAnchor();
        } else {
            uint256[3] memory genesisOpening = [ch.depositA, ch.depositB, uint256(0)];
            if (startNonce != 0 || startCommitment != poseidonT4.poseidon(genesisOpening)) revert InvalidChainAnchor();
        }

        if (!channelStateVerifier.verifyProof(a, b, c, pubSignals)) revert InvalidProof();

        outNonce = pubSignals[0];
        endCommitment = pubSignals[2];
    }

    /// @dev Pays out both parties. Deliberately does NOT let one party's
    ///      broken/malicious receive path revert the other party's payout —
    ///      each transfer is independent, falling back to a claimable credit
    ///      (`pendingWithdrawals`) rather than reverting the whole payout.
    ///      Without this, a single uncooperative party could permanently
    ///      freeze BOTH parties' funds by rejecting ETH.
    function _payout(Channel storage ch) internal {
        uint256 payA = ch.balanceA;
        uint256 payB = ch.balanceB;
        ch.balanceA = 0;
        ch.balanceB = 0;
        _creditOrSend(ch.partyA, payA);
        _creditOrSend(ch.partyB, payB);
    }

    /// @dev Attempts a direct push transfer with a bounded gas stipend (so a
    ///      malicious recipient can't grief via unbounded gas consumption
    ///      either). On failure, credits `pendingWithdrawals` instead of
    ///      reverting, so the OTHER party's payout in the same call is never
    ///      blocked. The recipient (or anyone, on their behalf) can later
    ///      call `claim()`.
    function _creditOrSend(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok,) = to.call{value: amount, gas: 30_000}("");
        if (ok) return;
        pendingWithdrawals[to] += amount;
        emit PayoutCredited(to, amount);
    }

    /// @notice Claim any funds that couldn't be pushed directly during a
    ///         payout (see `_creditOrSend`).
    function claim() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        if (amount == 0) revert NothingToClaim();
        pendingWithdrawals[msg.sender] = 0;

        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert ClaimTransferFailed();

        emit Claimed(msg.sender, amount);
    }

    /// @notice Canonical hash of a ChannelState, signed off-chain by both
    ///         parties. Includes `address(this)` and `block.chainid` as a
    ///         domain separator: without them, a signature valid for this
    ///         channel would also be valid for a same-numbered channelId on
    ///         ANY other deployment of this contract (e.g. this project's
    ///         own Chain A / Chain B instances in Milestone 3) as long as
    ///         the two parties' addresses happened to match — which is the
    ///         common case, since the same EOA key is routinely reused
    ///         across EVM chains. This is a standard EIP-712-style domain
    ///         binding, simplified (no full typed-data encoding) since this
    ///         demo doesn't need wallet-UI-friendly signing.
    function hashState(ChannelState calldata state) public view returns (bytes32) {
        return keccak256(
            abi.encode(address(this), block.chainid, state.channelId, state.nonce, state.balanceA, state.balanceB)
        );
    }
}
