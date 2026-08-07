// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PaymentChannel, IChannelStateVerifier, ILightClientVerifier} from "../src/PaymentChannel.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

contract PaymentChannelTest is Test {
    PaymentChannel channel;
    Groth16Verifier verifier;

    uint256 partyAKey = 0xA11CE;
    uint256 partyBKey = 0xB0B;
    address partyA;
    address partyB;

    // (0, 0) is PaymentChannel's explicit exemption for channels that never
    // use the ZK-proof close path and so never need a registered (and
    // ownership-proven) EdDSA key — see _verifyKeyOwnership. Every test in
    // this file only exercises the raw-signature path. See
    // test/ChannelStateProof.t.sol for the ZK-proof path with real keys.
    uint256 constant DUMMY_PUBKEY_AX = 0;
    uint256 constant DUMMY_PUBKEY_AY = 0;
    uint256 constant DUMMY_PUBKEY_BX = 0;
    uint256 constant DUMMY_PUBKEY_BY = 0;

    function setUp() public {
        verifier = new Groth16Verifier();
        channel = new PaymentChannel(IChannelStateVerifier(address(verifier)), ILightClientVerifier(address(0)));
        partyA = vm.addr(partyAKey);
        partyB = vm.addr(partyBKey);
        vm.deal(partyA, 10 ether);
        vm.deal(partyB, 10 ether);
    }

    function _openAndJoin(uint256 depositA, uint256 depositB) internal returns (uint256 channelId) {
        vm.prank(partyA);
        channelId = channel.open{value: depositA}(partyB, depositA, DUMMY_PUBKEY_AX, DUMMY_PUBKEY_AY, 0, 0, 0);

        vm.prank(partyB);
        channel.join{value: depositB}(channelId, DUMMY_PUBKEY_BX, DUMMY_PUBKEY_BY, 0, 0, 0);
    }

    function _sign(uint256 key, PaymentChannel.ChannelState memory state) internal view returns (bytes memory) {
        bytes32 digest = channel.hashState(
            PaymentChannel.ChannelState({
                channelId: state.channelId,
                nonce: state.nonce,
                balanceA: state.balanceA,
                balanceB: state.balanceB
            })
        );
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethDigest);
        return abi.encodePacked(r, s, v);
    }

    function test_openAndJoin_setsActive() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);
        (, , uint256 depositA, uint256 depositB, PaymentChannel.Status status, , uint256 balA, uint256 balB, , , , , ) =
            channel.channels(channelId);
        assertEq(depositA, 1 ether);
        assertEq(depositB, 1 ether);
        assertEq(uint256(status), uint256(PaymentChannel.Status.ACTIVE));
        assertEq(balA, 1 ether);
        assertEq(balB, 1 ether);
    }

    function test_cooperativeClose_settlesFinalBalances() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        // simulate an off-chain payment: A pays B 0.3 ETH
        PaymentChannel.ChannelState memory state = PaymentChannel.ChannelState({
            channelId: channelId,
            nonce: 1,
            balanceA: 0.7 ether,
            balanceB: 1.3 ether
        });
        bytes memory sigA = _sign(partyAKey, state);
        bytes memory sigB = _sign(partyBKey, state);

        uint256 balABefore = partyA.balance;
        uint256 balBBefore = partyB.balance;

        vm.prank(partyA);
        channel.closeCooperative(state, sigA, sigB);

        assertEq(partyA.balance, balABefore + 0.7 ether);
        assertEq(partyB.balance, balBBefore + 1.3 ether);

        (, , , , PaymentChannel.Status status, , , , , , , , ) = channel.channels(channelId);
        assertEq(uint256(status), uint256(PaymentChannel.Status.CLOSED));
    }

    function test_cooperativeClose_revertsOnBadSignature() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        PaymentChannel.ChannelState memory state = PaymentChannel.ChannelState({
            channelId: channelId,
            nonce: 1,
            balanceA: 0.7 ether,
            balanceB: 1.3 ether
        });
        bytes memory sigA = _sign(partyAKey, state);
        // wrong signer for B
        bytes memory badSigB = _sign(partyAKey, state);

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.InvalidSignatures.selector);
        channel.closeCooperative(state, sigA, badSigB);
    }

    function test_cooperativeClose_revertsOnConservationBreak() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        // balances don't sum to total deposits (2 ether) -> should revert
        PaymentChannel.ChannelState memory state = PaymentChannel.ChannelState({
            channelId: channelId,
            nonce: 1,
            balanceA: 0.7 ether,
            balanceB: 2 ether
        });
        bytes memory sigA = _sign(partyAKey, state);
        bytes memory sigB = _sign(partyBKey, state);

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.DepositMismatch.selector);
        channel.closeCooperative(state, sigA, sigB);
    }

    function test_unilateralClose_thenWithdrawAfterWindow() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        PaymentChannel.ChannelState memory state = PaymentChannel.ChannelState({
            channelId: channelId,
            nonce: 1,
            balanceA: 0.4 ether,
            balanceB: 1.6 ether
        });
        bytes memory sigA = _sign(partyAKey, state);
        bytes memory sigB = _sign(partyBKey, state);

        vm.prank(partyB);
        channel.closeUnilateral(state, sigA, sigB);

        // withdrawing before window expires must revert
        vm.prank(partyB);
        vm.expectRevert(PaymentChannel.ChallengeWindowOpen.selector);
        channel.withdraw(channelId);

        vm.warp(block.timestamp + channel.CHALLENGE_PERIOD() + 1);

        uint256 balABefore = partyA.balance;
        uint256 balBBefore = partyB.balance;

        vm.prank(partyB);
        channel.withdraw(channelId);

        assertEq(partyA.balance, balABefore + 0.4 ether);
        assertEq(partyB.balance, balBBefore + 1.6 ether);
    }

    function test_challenge_overridesStaleClose() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        // partyA tries to close with an OLD state favoring itself (stale/malicious)
        PaymentChannel.ChannelState memory staleState = PaymentChannel.ChannelState({
            channelId: channelId,
            nonce: 1,
            balanceA: 1.5 ether,
            balanceB: 0.5 ether
        });
        bytes memory staleSigA = _sign(partyAKey, staleState);
        bytes memory staleSigB = _sign(partyBKey, staleState);

        vm.prank(partyA);
        channel.closeUnilateral(staleState, staleSigA, staleSigB);

        // partyB challenges with the real latest state (higher nonce)
        PaymentChannel.ChannelState memory latestState = PaymentChannel.ChannelState({
            channelId: channelId,
            nonce: 2,
            balanceA: 0.2 ether,
            balanceB: 1.8 ether
        });
        bytes memory latestSigA = _sign(partyAKey, latestState);
        bytes memory latestSigB = _sign(partyBKey, latestState);

        vm.prank(partyB);
        channel.challenge(latestState, latestSigA, latestSigB);

        vm.warp(block.timestamp + channel.CHALLENGE_PERIOD() + 1);

        uint256 balABefore = partyA.balance;
        uint256 balBBefore = partyB.balance;

        vm.prank(partyA);
        channel.withdraw(channelId);

        assertEq(partyA.balance, balABefore + 0.2 ether);
        assertEq(partyB.balance, balBBefore + 1.8 ether);
    }

    /// @notice `challenge()` is deliberately NOT `onlyParty` (see its doc
    ///         comment in PaymentChannel.sol) — a third party holding a
    ///         validly co-signed newer state can submit it on a party's
    ///         behalf. This is what makes a third-party watchtower possible
    ///         (Milestone 4, see `watchtower/`) without it ever holding
    ///         either party's private key.
    function test_challenge_acceptedFromThirdPartyNotAChannelParty() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        PaymentChannel.ChannelState memory staleState =
            PaymentChannel.ChannelState({channelId: channelId, nonce: 1, balanceA: 1.5 ether, balanceB: 0.5 ether});
        bytes memory staleSigA = _sign(partyAKey, staleState);
        bytes memory staleSigB = _sign(partyBKey, staleState);

        vm.prank(partyA);
        channel.closeUnilateral(staleState, staleSigA, staleSigB);

        PaymentChannel.ChannelState memory latestState =
            PaymentChannel.ChannelState({channelId: channelId, nonce: 2, balanceA: 0.2 ether, balanceB: 1.8 ether});
        bytes memory latestSigA = _sign(partyAKey, latestState);
        bytes memory latestSigB = _sign(partyBKey, latestState);

        address watchtower = address(0xDEC0DE);
        assertTrue(watchtower != partyA && watchtower != partyB);

        vm.prank(watchtower);
        channel.challenge(latestState, latestSigA, latestSigB);

        (,,,,, uint256 nonce, uint256 balA, uint256 balB,,,,,) = channel.channels(channelId);
        assertEq(nonce, 2);
        assertEq(balA, 0.2 ether);
        assertEq(balB, 1.8 ether);
    }

    function test_challenge_revertsOnStaleNonce() public {
        uint256 channelId = _openAndJoin(1 ether, 1 ether);

        PaymentChannel.ChannelState memory state1 = PaymentChannel.ChannelState({
            channelId: channelId,
            nonce: 3,
            balanceA: 0.5 ether,
            balanceB: 1.5 ether
        });
        bytes memory sigA1 = _sign(partyAKey, state1);
        bytes memory sigB1 = _sign(partyBKey, state1);

        vm.prank(partyA);
        channel.closeUnilateral(state1, sigA1, sigB1);

        // attempt to challenge with an older or equal nonce must fail
        PaymentChannel.ChannelState memory staleChallenge = PaymentChannel.ChannelState({
            channelId: channelId,
            nonce: 3,
            balanceA: 0.9 ether,
            balanceB: 1.1 ether
        });
        bytes memory sigA2 = _sign(partyAKey, staleChallenge);
        bytes memory sigB2 = _sign(partyBKey, staleChallenge);

        vm.prank(partyB);
        vm.expectRevert(PaymentChannel.StaleNonce.selector);
        channel.challenge(staleChallenge, sigA2, sigB2);
    }
}
