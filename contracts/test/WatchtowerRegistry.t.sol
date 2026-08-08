// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PaymentChannel, IChannelStateVerifier, ILightClientVerifier} from "../src/PaymentChannel.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {WatchtowerRegistry} from "../src/WatchtowerRegistry.sol";

contract WatchtowerRegistryTest is Test {
    PaymentChannel channel;
    Groth16Verifier verifier;
    WatchtowerRegistry registry;

    uint256 partyAKey = 0xA11CE;
    uint256 partyBKey = 0xB0B;
    address partyA;
    address partyB;
    address watchtower = address(0x7A7C4);
    address rando = address(0xBEEF); // permissionless slash() caller

    uint256 constant DUMMY = 0;

    function setUp() public {
        verifier = new Groth16Verifier();
        channel = new PaymentChannel(IChannelStateVerifier(address(verifier)), ILightClientVerifier(address(0)));
        registry = new WatchtowerRegistry(channel);
        partyA = vm.addr(partyAKey);
        partyB = vm.addr(partyBKey);
        vm.deal(partyA, 10 ether);
        vm.deal(partyB, 10 ether);
        vm.deal(watchtower, 10 ether);
        vm.deal(rando, 1 ether);
    }

    function _openAndJoin(uint256 depositA, uint256 depositB) internal returns (uint256 channelId) {
        vm.prank(partyA);
        channelId = channel.open{value: depositA}(partyB, depositA, DUMMY, DUMMY, 0, 0, 0);
        vm.prank(partyB);
        channel.join{value: depositB}(channelId, DUMMY, DUMMY, 0, 0, 0);
    }

    function _sign(uint256 key, PaymentChannel.ChannelState memory state) internal view returns (bytes memory) {
        bytes32 digest = channel.hashState(state);
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethDigest);
        return abi.encodePacked(r, s, v);
    }

    function _state(uint256 channelId, uint256 nonce, uint256 balA, uint256 balB)
        internal
        pure
        returns (PaymentChannel.ChannelState memory)
    {
        return PaymentChannel.ChannelState({channelId: channelId, nonce: nonce, balanceA: balA, balanceB: balB});
    }

    // ---------------------------------------------------------------------
    // stake / unstake
    // ---------------------------------------------------------------------

    function test_stake_belowMinStake_reverts() public {
        vm.prank(watchtower);
        vm.expectRevert(WatchtowerRegistry.BelowMinStake.selector);
        registry.stake{value: 0.001 ether}(1);
    }

    function test_stake_accumulatesAcrossCalls() public {
        vm.startPrank(watchtower);
        registry.stake{value: 0.01 ether}(1);
        registry.stake{value: 0.02 ether}(1);
        vm.stopPrank();
        assertEq(registry.stakes(1, watchtower), 0.03 ether);
    }

    function test_unstake_revertsBeforeChannelClosed() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);
        vm.prank(watchtower);
        registry.stake{value: 0.01 ether}(channelId);

        // observeClosed() itself refuses while the channel isn't CLOSED yet...
        vm.expectRevert(WatchtowerRegistry.ChannelNotClosed.selector);
        registry.observeClosed(channelId);

        // ...so unstake() never even gets to the cooldown check.
        vm.prank(watchtower);
        vm.expectRevert(WatchtowerRegistry.NotYetObserved.selector);
        registry.unstake(channelId);
    }

    function test_unstake_revertsDuringCooldown_thenSucceedsAfter() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);
        vm.prank(watchtower);
        registry.stake{value: 0.01 ether}(channelId);

        PaymentChannel.ChannelState memory state = _state(channelId, 1, 1 ether, 1 ether);
        bytes memory sigA = _sign(partyAKey, state);
        bytes memory sigB = _sign(partyBKey, state);
        vm.prank(partyA);
        channel.closeCooperative(state, sigA, sigB);
        assertEq(uint256(channel.getChannel(channelId).status), uint256(PaymentChannel.Status.CLOSED));

        // unstake() refuses until *someone* has recorded the CLOSED
        // timestamp via observeClosed() — see its doc comment.
        vm.prank(watchtower);
        vm.expectRevert(WatchtowerRegistry.NotYetObserved.selector);
        registry.unstake(channelId);

        registry.observeClosed(channelId); // anyone can call this, e.g. rando

        vm.prank(watchtower);
        vm.expectRevert(WatchtowerRegistry.UnstakeCooldownActive.selector);
        registry.unstake(channelId);

        vm.warp(block.timestamp + registry.UNSTAKE_COOLDOWN() + 1);
        uint256 balBefore = watchtower.balance;
        vm.prank(watchtower);
        registry.unstake(channelId);
        assertEq(watchtower.balance, balBefore + 0.01 ether);
    }

    // ---------------------------------------------------------------------
    // commitCheckpoint
    // ---------------------------------------------------------------------

    function test_commitCheckpoint_revertsWithoutStake() public {
        vm.prank(watchtower);
        vm.expectRevert(WatchtowerRegistry.BelowMinStake.selector);
        registry.commitCheckpoint(1, 1, bytes32(uint256(1)));
    }

    function test_commitCheckpoint_revertsOnNonIncreasingNonce() public {
        vm.startPrank(watchtower);
        registry.stake{value: 0.01 ether}(1);
        registry.commitCheckpoint(1, 5, bytes32(uint256(1)));
        vm.expectRevert(WatchtowerRegistry.NonceNotIncreasing.selector);
        registry.commitCheckpoint(1, 5, bytes32(uint256(2)));
        vm.expectRevert(WatchtowerRegistry.NonceNotIncreasing.selector);
        registry.commitCheckpoint(1, 4, bytes32(uint256(2)));
        vm.stopPrank();
    }

    // ---------------------------------------------------------------------
    // slash — the core mechanism
    // ---------------------------------------------------------------------

    /// @notice The negligence scenario: watchtower committed to knowing
    ///         nonce 2 on-chain, but the channel nonetheless settled CLOSED
    ///         at nonce 1 (nobody, including the watchtower, challenged in
    ///         time) — permissionlessly slashable by anyone.
    function test_slash_whenChannelSettlesBelowCommittedNonce() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        vm.prank(watchtower);
        registry.stake{value: 1 ether}(channelId);
        vm.prank(watchtower);
        registry.commitCheckpoint(channelId, 2, keccak256("state at nonce 2"));

        // partyA closes unilaterally with a STALE state (nonce 1) — and
        // nobody (crucially, not even the staked watchtower) challenges
        // before the window closes.
        PaymentChannel.ChannelState memory stale = _state(channelId, 1, 0.9 ether, 1.1 ether);
        bytes memory staleSigA = _sign(partyAKey, stale);
        bytes memory staleSigB = _sign(partyBKey, stale);
        vm.prank(partyA);
        channel.closeUnilateral(stale, staleSigA, staleSigB);

        vm.warp(block.timestamp + channel.CHALLENGE_PERIOD() + 1);
        vm.prank(partyA);
        channel.withdraw(channelId);
        assertEq(uint256(channel.getChannel(channelId).status), uint256(PaymentChannel.Status.CLOSED));

        uint256 partyABefore = partyA.balance;
        uint256 partyBBefore = partyB.balance;
        uint256 randoBefore = rando.balance;

        vm.prank(rando); // permissionless — anyone can call slash()
        registry.slash(channelId, watchtower);

        assertEq(registry.stakes(channelId, watchtower), 0, "stake must be fully confiscated");
        assertEq(rando.balance, randoBefore + 0.1 ether, "caller earns SLASH_BOUNTY_BPS (10%) of 1 ether");
        assertEq(partyA.balance, partyABefore + 0.45 ether, "remainder split evenly, partyA half");
        assertEq(partyB.balance, partyBBefore + 0.45 ether, "remainder split evenly, partyB half");
    }

    /// @notice Regression test for a real finding from /code-review: slash()
    ///         must NOT punish a watchtower just because closeCooperative()
    ///         settled at a nonce below one it committed to — that path has
    ///         NO challenge window at all (both parties can co-sign an old
    ///         nonce and settle instantly), so the watchtower never had any
    ///         opportunity to intervene. Without this check, ANY channel
    ///         that simply chose to cooperatively settle at an earlier,
    ///         still-mutually-valid nonce than what a watchtower happened to
    ///         have on file would get that watchtower slashed for nothing.
    function test_slash_revertsOnCooperativeClose_evenBelowCommittedNonce() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        vm.prank(watchtower);
        registry.stake{value: 1 ether}(channelId);
        vm.prank(watchtower);
        registry.commitCheckpoint(channelId, 5, keccak256("state at nonce 5"));

        // Both parties cooperatively settle at an OLDER (but still validly
        // co-signed) nonce than what the watchtower committed to — entirely
        // legitimate, no fraud or missed challenge involved.
        PaymentChannel.ChannelState memory early = _state(channelId, 1, 0.9 ether, 1.1 ether);
        bytes memory earlySigA = _sign(partyAKey, early);
        bytes memory earlySigB = _sign(partyBKey, early);
        vm.prank(partyA);
        channel.closeCooperative(early, earlySigA, earlySigB);
        assertEq(uint256(channel.getChannel(channelId).status), uint256(PaymentChannel.Status.CLOSED));

        vm.expectRevert(WatchtowerRegistry.WatchtowerNotNegligent.selector);
        registry.slash(channelId, watchtower);
    }

    function test_slash_revertsIfChannelSettledAtOrAboveCommittedNonce() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        vm.prank(watchtower);
        registry.stake{value: 1 ether}(channelId);
        vm.prank(watchtower);
        registry.commitCheckpoint(channelId, 1, keccak256("state at nonce 1"));

        // The watchtower did its job: it (or anyone) got the SAME nonce it
        // committed to settled on-chain — not negligent.
        PaymentChannel.ChannelState memory state = _state(channelId, 1, 0.9 ether, 1.1 ether);
        bytes memory sigA = _sign(partyAKey, state);
        bytes memory sigB = _sign(partyBKey, state);
        vm.prank(partyA);
        channel.closeCooperative(state, sigA, sigB);

        vm.expectRevert(WatchtowerRegistry.WatchtowerNotNegligent.selector);
        registry.slash(channelId, watchtower);
    }

    function test_slash_revertsWithoutStake() public {
        vm.expectRevert(WatchtowerRegistry.NothingStaked.selector);
        registry.slash(1, watchtower);
    }

    function test_slash_revertsWithoutCommitment() public {
        vm.prank(watchtower);
        registry.stake{value: 0.01 ether}(1);

        vm.expectRevert(WatchtowerRegistry.NoCommitment.selector);
        registry.slash(1, watchtower);
    }

    function test_slash_revertsBeforeChannelClosed() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);
        vm.prank(watchtower);
        registry.stake{value: 1 ether}(channelId);
        vm.prank(watchtower);
        registry.commitCheckpoint(channelId, 2, keccak256("state"));

        vm.expectRevert(WatchtowerRegistry.ChannelNotClosed.selector);
        registry.slash(channelId, watchtower);
    }

    /// @notice A watchtower that DID submit the rescuing challenge in time
    ///         ends up with the channel settling at ITS OWN committed
    ///         nonce, not below it — so it's never slashable for doing its
    ///         job right, even though it also called commitCheckpoint.
    function test_slash_notPossible_whenWatchtowerActuallyChallengedSuccessfully() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);
        vm.prank(watchtower);
        registry.stake{value: 1 ether}(channelId);
        vm.prank(watchtower);
        registry.commitCheckpoint(channelId, 2, keccak256("state at nonce 2"));

        PaymentChannel.ChannelState memory stale = _state(channelId, 1, 0.9 ether, 1.1 ether);
        bytes memory staleSigA = _sign(partyAKey, stale);
        bytes memory staleSigB = _sign(partyBKey, stale);
        vm.prank(partyA);
        channel.closeUnilateral(stale, staleSigA, staleSigB);

        // Watchtower rescues with the newer, correct state (this is exactly
        // what watchtower/src/monitor.ts automates) — note it's NOT a party,
        // channel.challenge() deliberately allows third-party callers.
        PaymentChannel.ChannelState memory fresh = _state(channelId, 2, 0.8 ether, 1.2 ether);
        bytes memory freshSigA = _sign(partyAKey, fresh);
        bytes memory freshSigB = _sign(partyBKey, fresh);
        vm.prank(watchtower);
        channel.challenge(fresh, freshSigA, freshSigB);

        vm.warp(block.timestamp + channel.CHALLENGE_PERIOD() + 1);
        vm.prank(partyA);
        channel.withdraw(channelId);

        vm.expectRevert(WatchtowerRegistry.WatchtowerNotNegligent.selector);
        registry.slash(channelId, watchtower);
    }
}
