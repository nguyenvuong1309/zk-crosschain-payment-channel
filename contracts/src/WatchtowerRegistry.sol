// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PaymentChannel} from "./PaymentChannel.sol";

/// @title WatchtowerRegistry
/// @notice Gives a watchtower (see `watchtower/`, PLAN.md Milestone 4)
///         economic skin in the game, instead of running purely on trust
///         that it stays online and honest.
///
/// Problem this closes: today, `watchtower/` is a free-to-run, free-to-quit
/// service. Nothing on-chain distinguishes a watchtower that reliably
/// challenges stale closes from one that's offline, malicious, or never
/// existed — a party trusting a watchtower has no way to verify that trust
/// is warranted, and no recourse if it's misplaced (see docs/threat-model.md
/// #2's residual liveness risk).
///
/// How this fixes it, and its real limits:
///   1. `stake()` — a watchtower locks ETH against a specific channel it's
///      promising to watch. Anyone can check `stakes[channelId][watchtower]`
///      on-chain before trusting that watchtower for that channel.
///   2. `commitCheckpoint()` — every time the watchtower receives a new
///      off-chain update (the same moment `watchtower/src/checkpoint.ts`
///      already verifies and stores it locally), it ALSO submits a cheap
///      on-chain commitment: just `(nonce, keccak256(state))`, not the full
///      state. This is a real, deliberate cost this design adds — one L1 tx
///      per off-chain update, for the watchtower only (parties themselves
///      still pay nothing per update) — the price of making "the watchtower
///      knew about a newer state and didn't act" provable on-chain instead
///      of an unverifiable off-chain claim.
///   3. `slash()` — permissionless. If a channel ends up CLOSED (challenge
///      window definitively over, see `PaymentChannel.withdraw`/
///      `withdrawWithOpening`) settled at a nonce LOWER than a nonce the
///      watchtower itself committed to on-chain, that is on-chain proof the
///      watchtower had strictly-better information and failed to submit a
///      challenge in time. Anyone can call `slash()` to confiscate that
///      watchtower's stake for that channel; the caller earns a bounty for
///      policing this (see `SLASH_BOUNTY_BPS`), and the remainder goes to
///      the channel's two parties — the ones actually harmed by the missed
///      challenge.
///
/// What this does NOT cover (documented, not hidden):
///   - A watchtower that simply never commits any checkpoint can't be
///     slashed by this contract — `slash()` only proves negligence relative
///     to what the watchtower itself put on-chain. It's still strictly
///     better than the pre-existing all-or-nothing trust model: a watchtower
///     that WANTS stake-backed credibility now can earn it verifiably, and
///     one that skips checkpointing is visibly not doing so (an empty
///     `commitments` history for a channel it claims to protect is itself a
///     public signal).
///   - Does not by itself pay a watchtower for successful challenges — that
///     reward path would need `PaymentChannel.sol` itself to escrow a bounty
///     at open time (see PLAN.md's list of further upgrades); parties can
///     still pay a watchtower for its service through any off-chain
///     arrangement they like, same as before this contract existed.
contract WatchtowerRegistry {
    PaymentChannel public immutable paymentChannel;

    /// @notice Minimum stake to be slashable for a channel — mostly a
    ///         dust-attack guard (a near-zero "stake" would make the whole
    ///         mechanism pointless: nothing meaningful at risk).
    uint256 public constant MIN_STAKE = 0.01 ether;

    /// @notice Share of a slashed stake paid to whoever calls `slash()`,
    ///         in basis points — the incentive for slashing to actually get
    ///         called instead of a confirmed-negligent watchtower's stake
    ///         just sitting there unclaimed forever.
    uint256 public constant SLASH_BOUNTY_BPS = 1_000; // 10%
    uint256 internal constant BPS_DENOMINATOR = 10_000;

    /// @notice How long after a channel is first observed CLOSED that
    ///         `unstake()` stays blocked, giving anyone a window to call
    ///         `slash()` first — without this, a negligent watchtower could
    ///         race to `unstake()` the instant CLOSED becomes true, the same
    ///         block `slash()` also becomes callable in. Mirrors
    ///         `PaymentChannel.CHALLENGE_PERIOD`'s spirit (a fixed grace
    ///         window before funds are considered final) rather than reusing
    ///         its value, since this is watching a different event
    ///         (CLOSED, not the original close attempt).
    uint256 public constant UNSTAKE_COOLDOWN = 1 days;

    struct Commitment {
        uint256 nonce;
        bytes32 stateHash;
    }

    // channelId => watchtower => staked amount currently locked for that channel
    mapping(uint256 => mapping(address => uint256)) public stakes;
    // channelId => watchtower => highest checkpoint committed on-chain so far
    mapping(uint256 => mapping(address => Commitment)) public commitments;
    // channelId => timestamp this contract first observed the channel CLOSED
    // (0 if never observed yet) — see UNSTAKE_COOLDOWN.
    mapping(uint256 => uint256) public closedObservedAt;

    /// @notice Funds `slash()` couldn't push directly to a recipient (bounty
    ///         caller or either channel party) — see `_creditOrSend`. Claim
    ///         via `claim()`.
    mapping(address => uint256) public pendingCredits;

    event Staked(uint256 indexed channelId, address indexed watchtower, uint256 amount);
    event Unstaked(uint256 indexed channelId, address indexed watchtower, uint256 amount);
    event CheckpointCommitted(uint256 indexed channelId, address indexed watchtower, uint256 nonce, bytes32 stateHash);
    event Slashed(
        uint256 indexed channelId,
        address indexed watchtower,
        uint256 bounty,
        uint256 partyShare,
        address indexed caller
    );
    event PayoutCredited(address indexed to, uint256 amount);
    event Claimed(address indexed to, uint256 amount);

    error BelowMinStake();
    error NothingStaked();
    error ChannelNotClosed();
    error NonceNotIncreasing();
    error NoCommitment();
    error WatchtowerNotNegligent();
    error TransferFailed();
    error UnstakeCooldownActive();
    error NotYetObserved();
    error NothingToClaim();
    error ClaimTransferFailed();

    constructor(PaymentChannel _paymentChannel) {
        paymentChannel = _paymentChannel;
    }

    /// @notice Lock stake against `channelId`. Callable multiple times to
    ///         top up; `msg.sender` is the watchtower identity being staked.
    function stake(uint256 channelId) external payable {
        stakes[channelId][msg.sender] += msg.value;
        if (stakes[channelId][msg.sender] < MIN_STAKE) revert BelowMinStake();
        emit Staked(channelId, msg.sender, msg.value);
    }

    /// @notice Records, once, the timestamp this contract first observes
    ///         `channelId` as CLOSED — starting `UNSTAKE_COOLDOWN`'s clock.
    ///         Callable by anyone, any time; a no-op (not a revert) if
    ///         already recorded. Split out from `unstake()`/`slash()` on
    ///         purpose: a call that reverts (e.g. `unstake()` failing its
    ///         own cooldown check) rolls back EVERY storage write it made,
    ///         including this one — so the first-ever `unstake()` attempt
    ///         right after closing could never durably record the
    ///         timestamp it needs to eventually succeed. Calling this
    ///         directly (or via `slash()`, which also calls it, and does
    ///         succeed on its non-cooldown-gated paths) records it in a
    ///         transaction that doesn't depend on the cooldown outcome.
    function observeClosed(uint256 channelId) external returns (uint256 closedAt) {
        return _observeClosed(channelId);
    }

    /// @notice Withdraw stake once the channel no longer needs watching
    ///         (CLOSED — the challenge window that stake was backing is
    ///         over) AND `UNSTAKE_COOLDOWN` has passed since CLOSED was
    ///         first observed. Requires `observeClosed(channelId)` (or a
    ///         SUCCESSFUL `slash()` call, which also records it) to have
    ///         happened first, in an earlier transaction — see
    ///         `observeClosed`'s doc comment for why this can't just happen
    ///         automatically inside `unstake()` itself.
    ///         This two-step shape is what gives `slash()` first refusal on
    ///         a negligent watchtower's stake instead of a same-block race.
    function unstake(uint256 channelId) external {
        uint256 amount = stakes[channelId][msg.sender];
        if (amount == 0) revert NothingStaked();
        uint256 closedAt = closedObservedAt[channelId];
        // Not auto-recorded here on purpose — see `observeClosed`'s doc
        // comment: this call must be able to revert on the cooldown check
        // below without silently discarding a fresh recording in the same
        // transaction. Caller must have called `observeClosed()` (or
        // `slash()`, which also records it) in an earlier transaction.
        if (closedAt == 0) revert NotYetObserved();
        if (block.timestamp < closedAt + UNSTAKE_COOLDOWN) revert UnstakeCooldownActive();

        stakes[channelId][msg.sender] = 0;
        emit Unstaked(channelId, msg.sender, amount);

        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @notice Commit on-chain to having seen off-chain state `nonce` for
    ///         `channelId`, identified by `stateHash` (the same digest
    ///         `PaymentChannel.hashState()` would produce for it — NOT
    ///         re-derived or checked here, since this contract never sees
    ///         the actual balances; only used later, in `slash()`, purely as
    ///         a nonce watermark). Must be called with a strictly increasing
    ///         nonce per watchtower per channel, mirroring the "nonce must
    ///         increase" invariant `PaymentChannel.sol` itself enforces.
    /// @dev Requires an active stake so a watchtower can't rack up
    ///      commitments risk-free, then stake only right before a slash
    ///      attempt would land — `MIN_STAKE` must already be locked.
    function commitCheckpoint(uint256 channelId, uint256 nonce, bytes32 stateHash) external {
        if (stakes[channelId][msg.sender] < MIN_STAKE) revert BelowMinStake();
        if (nonce <= commitments[channelId][msg.sender].nonce) revert NonceNotIncreasing();

        commitments[channelId][msg.sender] = Commitment(nonce, stateHash);
        emit CheckpointCommitted(channelId, msg.sender, nonce, stateHash);
    }

    /// @notice Permissionlessly slash `watchtower`'s stake for `channelId` if
    ///         the channel settled CLOSED at a nonce lower than the highest
    ///         nonce that watchtower itself committed to on-chain — proof it
    ///         knew of a newer state and never got a challenge in before the
    ///         window closed.
    /// @dev Excludes channels that settled via `closeCooperative`
    ///      (`ch.closedCooperatively`) — that path accepts ANY mutually
    ///      co-signed nonce with NO challenge window at all (see
    ///      PaymentChannel.sol's `closeCooperative`), so a channel can
    ///      legitimately settle at a nonce below one a watchtower has on
    ///      file simply because both parties chose to, not because the
    ///      watchtower missed a real opportunity to challenge. Without this
    ///      check, two parties (or a channel that simply never needed the
    ///      watchtower) could get an honest watchtower slashed for a
    ///      "negligence" it never had any chance to prevent.
    function slash(uint256 channelId, address watchtower) external {
        uint256 staked = stakes[channelId][watchtower];
        if (staked == 0) revert NothingStaked();

        Commitment memory c = commitments[channelId][watchtower];
        if (c.nonce == 0) revert NoCommitment();

        _observeClosed(channelId);
        PaymentChannel.Channel memory ch = paymentChannel.getChannel(channelId);
        if (ch.closedCooperatively) revert WatchtowerNotNegligent();
        if (ch.nonce >= c.nonce) revert WatchtowerNotNegligent();

        stakes[channelId][watchtower] = 0;

        uint256 bounty = (staked * SLASH_BOUNTY_BPS) / BPS_DENOMINATOR;
        uint256 partyShare = staked - bounty;
        uint256 partyA_share = partyShare / 2;
        uint256 partyB_share = partyShare - partyA_share;

        emit Slashed(channelId, watchtower, bounty, partyShare, msg.sender);

        // Deliberately does NOT let one recipient's broken/malicious receive
        // path revert the whole slash — each transfer is independent,
        // falling back to a claimable credit (`pendingCredits`) rather than
        // reverting the whole call. Without this, a negligent watchtower
        // could permanently immunize itself from slashing by making itself
        // (or colluding with) a channel party whose address rejects ETH —
        // see PaymentChannel._creditOrSend, which this mirrors.
        _creditOrSend(msg.sender, bounty);
        _creditOrSend(ch.partyA, partyA_share);
        _creditOrSend(ch.partyB, partyB_share);
    }

    /// @notice Claim any funds that couldn't be pushed directly during a
    ///         `slash()` payout (see `_creditOrSend`).
    function claim() external {
        uint256 amount = pendingCredits[msg.sender];
        if (amount == 0) revert NothingToClaim();
        pendingCredits[msg.sender] = 0;

        (bool ok,) = msg.sender.call{value: amount}("");
        if (!ok) revert ClaimTransferFailed();

        emit Claimed(msg.sender, amount);
    }

    /// @dev Reverts unless `channelId` is currently CLOSED; records (once)
    ///      the timestamp this contract first observed that, and returns it
    ///      (whether just-recorded or previously recorded) — see
    ///      `UNSTAKE_COOLDOWN`.
    function _observeClosed(uint256 channelId) internal returns (uint256 closedAt) {
        closedAt = closedObservedAt[channelId];
        if (closedAt != 0) return closedAt;

        PaymentChannel.Channel memory ch = paymentChannel.getChannel(channelId);
        if (ch.status != PaymentChannel.Status.CLOSED) revert ChannelNotClosed();

        closedAt = block.timestamp;
        closedObservedAt[channelId] = closedAt;
    }

    function _send(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok,) = to.call{value: amount}("");
        if (!ok) revert TransferFailed();
    }

    /// @dev Attempts a direct push transfer with a bounded gas stipend (so a
    ///      malicious recipient can't grief via unbounded gas consumption
    ///      either). On failure, credits `pendingCredits` instead of
    ///      reverting, so the OTHER recipients' shares in the same `slash()`
    ///      call are never blocked. The recipient (or anyone, on their
    ///      behalf) can later call `claim()`.
    function _creditOrSend(address to, uint256 amount) internal {
        if (amount == 0) return;
        (bool ok,) = to.call{value: amount, gas: 30_000}("");
        if (ok) return;
        pendingCredits[to] += amount;
        emit PayoutCredited(to, amount);
    }
}
