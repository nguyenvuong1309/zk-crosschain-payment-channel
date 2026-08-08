// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PaymentChannel, IChannelStateVerifier, ILightClientVerifier} from "../src/PaymentChannel.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

/// @notice A "receiver" that always reverts, and consumes plenty of gas
///         while doing so — models a malicious or simply broken counterparty
///         used to exercise the poison-pill payout fix.
contract RevertingReceiver {
    receive() external payable {
        revert("nope");
    }
}

contract PaymentChannelSecurityFixesTest is Test {
    PaymentChannel channel;
    Groth16Verifier verifier;

    uint256 partyAKey = 0xA11CE;
    uint256 partyBKey = 0xB0B;
    address partyA;
    address partyB;

    function setUp() public {
        verifier = new Groth16Verifier();
        channel = new PaymentChannel(IChannelStateVerifier(address(verifier)), ILightClientVerifier(address(0)));
        partyA = vm.addr(partyAKey);
        partyB = vm.addr(partyBKey);
        vm.deal(partyA, 10 ether);
        vm.deal(partyB, 10 ether);
    }

    function _sign(uint256 key, PaymentChannel.ChannelState memory state) internal view returns (bytes memory) {
        bytes32 digest = channel.hashState(
            PaymentChannel.ChannelState({
                channelId: state.channelId, nonce: state.nonce, balanceA: state.balanceA, balanceB: state.balanceB
            })
        );
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, ethDigest);
        return abi.encodePacked(r, s, v);
    }

    // --- Fix A: domain separator prevents cross-deployment signature replay ---

    function test_hashState_differsAcrossDeployments_forSameChannelData() public {
        PaymentChannel otherChannel =
            new PaymentChannel(IChannelStateVerifier(address(verifier)), ILightClientVerifier(address(0)));

        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: 1, nonce: 1, balanceA: 1 ether, balanceB: 1 ether});

        bytes32 hashOnChannel = channel.hashState(state);
        bytes32 hashOnOtherChannel = otherChannel.hashState(state);

        // Same channelId/nonce/balances, different contract instance (stand-in
        // for "same channelId on Chain A vs Chain B") must hash differently —
        // otherwise a signature from one is valid on the other.
        assertTrue(hashOnChannel != hashOnOtherChannel);
    }

    function test_closeCooperative_revertsWhenSignatureIsFromAnotherDeployment() public {
        // Channel on "Chain A" (this `channel`) and an identical one on a
        // second deployment standing in for "Chain B".
        PaymentChannel channelOnChainB =
            new PaymentChannel(IChannelStateVerifier(address(verifier)), ILightClientVerifier(address(0)));

        vm.prank(partyA);
        uint256 channelId = channel.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channel.join{value: 1 ether}(channelId, 0, 0, 0, 0, 0);

        vm.prank(partyA);
        uint256 channelIdOnB = channelOnChainB.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channelOnChainB.join{value: 1 ether}(channelIdOnB, 0, 0, 0, 0, 0);
        require(
            channelIdOnB == channelId,
            "test setup: channel ids must match to prove the replay is blocked by domain, not id"
        );

        // Sign a state using channelOnChainB's domain (its hashState).
        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: channelId, nonce: 1, balanceA: 0.5 ether, balanceB: 1.5 ether});
        bytes32 digestOnB = channelOnChainB.hashState(state);
        bytes32 ethDigestOnB = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digestOnB));
        (uint8 vA, bytes32 rA, bytes32 sA) = vm.sign(partyAKey, ethDigestOnB);
        (uint8 vB, bytes32 rB, bytes32 sB) = vm.sign(partyBKey, ethDigestOnB);
        bytes memory sigA = abi.encodePacked(rA, sA, vA);
        bytes memory sigB = abi.encodePacked(rB, sB, vB);

        // Replaying those same signatures against `channel` (Chain A) must
        // fail — pre-fix, this would have succeeded since both used the
        // identical unsalted hash.
        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.InvalidSignatures.selector);
        channel.closeCooperative(state, sigA, sigB);
    }

    // --- Fix B: one party's broken receive() can no longer freeze both parties' funds ---

    /// @dev Signature validity only depends on the recovered address
    ///      matching `ch.partyB`, not on whether that address currently
    ///      holds contract code — so we can sign as a normal EOA and THEN
    ///      `vm.etch` a reverting contract onto that same address, to
    ///      reproduce "counterparty's receive() reverts" while still going
    ///      through the real, signature-gated `closeCooperative` → `_payout`
    ///      path (not a side door like `cancelUnjoined`).
    function test_closeCooperative_stillPaysHonestParty_whenCounterpartyRejectsEth() public {
        vm.prank(partyA);
        uint256 channelId = channel.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channel.join{value: 1 ether}(channelId, 0, 0, 0, 0, 0);

        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: channelId, nonce: 1, balanceA: 0.5 ether, balanceB: 1.5 ether});
        bytes memory sigA = _sign(partyAKey, state);
        bytes memory sigB = _sign(partyBKey, state);

        // NOW turn partyB's address into a contract that rejects ETH.
        vm.etch(partyB, address(new RevertingReceiver()).code);

        uint256 balABefore = partyA.balance;

        vm.prank(partyA);
        channel.closeCooperative(state, sigA, sigB);

        // partyA still gets paid directly...
        assertEq(partyA.balance, balABefore + 0.5 ether);
        // ...and partyB's share is credited instead of reverting the whole close.
        assertEq(channel.pendingWithdrawals(partyB), 1.5 ether);

        assertEq(uint256(channel.getChannel(channelId).status), uint256(PaymentChannel.Status.CLOSED));
    }

    function test_cancelUnjoined_creditsPartyA_whenPartyAItselfRejectsEth() public {
        RevertingReceiver badA = new RevertingReceiver();
        vm.deal(address(badA), 1 ether);

        vm.prank(address(badA));
        uint256 channelId = channel.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);

        // partyA (badA) cancels before partyB joins; the refund push to
        // badA itself will fail, and MUST be credited rather than reverting
        // the whole cancellation.
        vm.prank(address(badA));
        channel.cancelUnjoined(channelId);

        assertEq(channel.pendingWithdrawals(address(badA)), 1 ether);

        assertEq(uint256(channel.getChannel(channelId).status), uint256(PaymentChannel.Status.CLOSED));
    }

    function test_claim_paysOutCreditedFunds() public {
        vm.prank(partyA);
        uint256 channelId = channel.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channel.join{value: 1 ether}(channelId, 0, 0, 0, 0, 0);

        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: channelId, nonce: 1, balanceA: 0.5 ether, balanceB: 1.5 ether});
        bytes memory sigA = _sign(partyAKey, state);
        bytes memory sigB = _sign(partyBKey, state);

        vm.etch(partyB, address(new RevertingReceiver()).code);

        vm.prank(partyA);
        channel.closeCooperative(state, sigA, sigB);
        assertEq(channel.pendingWithdrawals(partyB), 1.5 ether);

        // partyB fixes itself (back to a plain address with no code) and claims.
        vm.etch(partyB, "");
        uint256 balBefore = partyB.balance;

        vm.prank(partyB);
        channel.claim();

        assertEq(partyB.balance, balBefore + 1.5 ether);
        assertEq(channel.pendingWithdrawals(partyB), 0);
    }

    function test_claim_revertsWhenNothingToClaim() public {
        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.NothingToClaim.selector);
        channel.claim();
    }

    // --- Fix C: cancelUnjoined lets partyA reclaim funds if partyB never joins ---

    function test_cancelUnjoined_refundsPartyA() public {
        vm.prank(partyA);
        uint256 channelId = channel.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);

        uint256 balBefore = partyA.balance;

        vm.prank(partyA);
        channel.cancelUnjoined(channelId);

        assertEq(partyA.balance, balBefore + 1 ether);
    }

    function test_cancelUnjoined_revertsIfPartyBAlreadyJoined() public {
        vm.prank(partyA);
        uint256 channelId = channel.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channel.join{value: 1 ether}(channelId, 0, 0, 0, 0, 0);

        vm.prank(partyA);
        vm.expectRevert(
            abi.encodeWithSelector(
                PaymentChannel.WrongStatus.selector, PaymentChannel.Status.UNINITIALIZED, PaymentChannel.Status.ACTIVE
            )
        );
        channel.cancelUnjoined(channelId);
    }

    function test_cancelUnjoined_revertsForNonPartyA() public {
        vm.prank(partyA);
        uint256 channelId = channel.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);

        vm.prank(partyB);
        vm.expectRevert(PaymentChannel.InvalidParty.selector);
        channel.cancelUnjoined(channelId);
    }
}
