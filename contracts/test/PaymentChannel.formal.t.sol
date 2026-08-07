// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PaymentChannel, IChannelStateVerifier, ILightClientVerifier} from "../src/PaymentChannel.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

/// @notice Symbolic ("formal") property tests for PaymentChannel.sol,
///         Milestone 4 — see PLAN.md and docs/threat-model.md's "Formal
///         verification (Milestone 4)" section (NOT #3, which is about
///         `channel_state.circom`, a different artifact).
///
///         Unlike the concrete example tests elsewhere in this directory
///         (PaymentChannel.t.sol etc — "this ONE scenario behaves
///         correctly"), every `check_*` function here is run by Halmos
///         (bounded symbolic execution over EVM bytecode) with ALL its
///         parameters treated as symbolic: Halmos explores (up to its
///         configured bounds) every value a real attacker could choose and
///         proves the asserted property holds for all of them.
///
///         Run (from contracts/, requires a recent `pip install halmos` —
///         NOT part of `forge test`): `halmos --contract PaymentChannelFormalTest`
///
///         Deliberate scope limits:
///           - `channel_state.circom`'s correctness (arithmetic circuit
///             constraints) is out of reach — Halmos reasons about EVM
///             bytecode, not circom.
///           - Halmos treats `ecrecover` as an UNINTERPRETED function: it
///             can make ANY (r,s,v,digest) "recover" to ANY target address,
///             regardless of real ECDSA validity (computing real elliptic-
///             curve recovery symbolically is intractable — this is a
///             documented, common trade-off for bounded symbolic execution
///             tools, not specific to this codebase). Early drafts of this
///             suite tried to prove "closeCooperative() with a fully
///             symbolic signature either reverts or preserves conservation"
///             — Halmos found "counterexamples" that only exist because it
///             can freely fake ANY signature, including ones no real private
///             key could ever produce. Every property below is written to
///             be TRUE regardless of how permissively `ecrecover` is
///             modeled — by proving checks that happen unconditionally
///             (nonce/status/conservation guards), not by relying on
///             signature forgery being impossible.
contract PaymentChannelFormalTest is Test {
    PaymentChannel channel;
    Groth16Verifier verifier;

    address partyA;
    address partyB;
    uint256 constant DEPOSIT_A = 1 ether;
    uint256 constant DEPOSIT_B = 1 ether;
    uint256 channelId;

    function setUp() public {
        verifier = new Groth16Verifier();
        channel = new PaymentChannel(IChannelStateVerifier(address(verifier)), ILightClientVerifier(address(0)));

        partyA = address(0xA11CE);
        partyB = address(0xB0B);
        vm.deal(partyA, DEPOSIT_A);
        vm.deal(partyB, DEPOSIT_B);

        vm.prank(partyA);
        channelId = channel.open{value: DEPOSIT_A}(partyB, DEPOSIT_A, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channel.join{value: DEPOSIT_B}(channelId, 0, 0, 0, 0, 0);
    }

    /// @notice closeCooperative() can NEVER succeed with a state whose
    ///         balances don't sum to the channel's total deposits — for ANY
    ///         symbolic (nonce, balanceA, balanceB, sigA, sigB), including
    ///         signatures Halmos is free to treat as "valid" regardless of
    ///         real-world forgeability (see contract-level doc comment).
    ///         This holds unconditionally because `_checkConservation`'s
    ///         `require`-equivalent is plain deterministic arithmetic, not
    ///         gated on signature validity being "real".
    function check_closeCooperative_revertsIfConservationViolated(
        uint256 nonce,
        uint256 balanceA,
        uint256 balanceB,
        bytes memory sigA,
        bytes memory sigB
    ) public {
        vm.assume(balanceA + balanceB != DEPOSIT_A + DEPOSIT_B);
        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: channelId, nonce: nonce, balanceA: balanceA, balanceB: balanceB});

        vm.prank(partyA);
        try channel.closeCooperative(state, sigA, sigB) {
            assert(false); // unreachable — conservation is violated, this must revert
        } catch {}
    }

    /// @notice Same property for closeUnilateral() — the entry point into
    ///         the challenge-period path.
    function check_closeUnilateral_revertsIfConservationViolated(
        uint256 nonce,
        uint256 balanceA,
        uint256 balanceB,
        bytes memory sigA,
        bytes memory sigB
    ) public {
        vm.assume(balanceA + balanceB != DEPOSIT_A + DEPOSIT_B);
        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: channelId, nonce: nonce, balanceA: balanceA, balanceB: balanceB});

        vm.prank(partyA);
        try channel.closeUnilateral(state, sigA, sigB) {
            assert(false);
        } catch {}
    }

    /// @notice Once a channel reaches CLOSED status, withdraw() can never
    ///         succeed again — the classic double-spend/double-payout check.
    ///         `caller` ranges over the channel's own two parties (withdraw
    ///         is `onlyParty`; a third-party caller is already rejected by
    ///         that modifier, tested concretely elsewhere).
    function check_withdraw_cannotSucceedTwice(address caller) public {
        uint256 keyA = 0xA11CE;
        uint256 keyB = 0xB0B;
        address derivedA = vm.addr(keyA);
        address derivedB = vm.addr(keyB);
        vm.deal(derivedA, DEPOSIT_A);
        vm.deal(derivedB, DEPOSIT_B);

        vm.prank(derivedA);
        uint256 cid = channel.open{value: DEPOSIT_A}(derivedB, DEPOSIT_A, 0, 0, 0, 0, 0);
        vm.prank(derivedB);
        channel.join{value: DEPOSIT_B}(cid, 0, 0, 0, 0, 0);

        PaymentChannel.ChannelState memory realState =
            PaymentChannel.ChannelState({channelId: cid, nonce: 1, balanceA: 0.5 ether, balanceB: 1.5 ether});
        bytes32 realDigest = channel.hashState(realState);
        bytes32 realEthDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", realDigest));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(keyA, realEthDigest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(keyB, realEthDigest);

        vm.prank(derivedA);
        channel.closeUnilateral(realState, abi.encodePacked(r1, s1, v1), abi.encodePacked(r2, s2, v2));

        vm.warp(block.timestamp + channel.CHALLENGE_PERIOD() + 1);
        vm.prank(derivedA);
        channel.withdraw(cid); // first withdraw — must succeed

        // Now CLOSED. Even a legitimate party can't withdraw twice.
        vm.assume(caller == derivedA || caller == derivedB);
        vm.prank(caller);
        try channel.withdraw(cid) {
            assert(false);
        } catch {}
    }

    /// @notice During the challenge window, challenge() can NEVER succeed
    ///         with a nonce that's not strictly greater than the currently
    ///         posted one — for ANY symbolic candidate nonce/balances/
    ///         signatures/caller (challenge() is deliberately not
    ///         `onlyParty`, see its doc comment — a third-party watchtower
    ///         must be able to call it). This holds unconditionally because
    ///         the nonce check happens BEFORE signature verification in the
    ///         contract, so it's immune to Halmos's permissive ecrecover
    ///         model (see contract-level doc comment).
    function check_challenge_revertsOnNonIncreasingNonce(
        uint256 candidateNonce,
        uint256 balanceA,
        uint256 balanceB,
        bytes memory sigA,
        bytes memory sigB,
        address caller
    ) public {
        uint256 keyA = 0xA11CE;
        uint256 keyB = 0xB0B;
        address derivedA = vm.addr(keyA);
        address derivedB = vm.addr(keyB);
        vm.deal(derivedA, DEPOSIT_A);
        vm.deal(derivedB, DEPOSIT_B);

        vm.prank(derivedA);
        uint256 cid = channel.open{value: DEPOSIT_A}(derivedB, DEPOSIT_A, 0, 0, 0, 0, 0);
        vm.prank(derivedB);
        channel.join{value: DEPOSIT_B}(cid, 0, 0, 0, 0, 0);

        PaymentChannel.ChannelState memory openingState =
            PaymentChannel.ChannelState({channelId: cid, nonce: 5, balanceA: 0.5 ether, balanceB: 1.5 ether});
        bytes32 digest = channel.hashState(openingState);
        bytes32 ethDigest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", digest));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(keyA, ethDigest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(keyB, ethDigest);

        vm.prank(derivedA);
        channel.closeUnilateral(openingState, abi.encodePacked(r1, s1, v1), abi.encodePacked(r2, s2, v2));

        vm.assume(candidateNonce <= 5);
        PaymentChannel.ChannelState memory candidate = PaymentChannel.ChannelState({
            channelId: cid, nonce: candidateNonce, balanceA: balanceA, balanceB: balanceB
        });

        vm.prank(caller);
        try channel.challenge(candidate, sigA, sigB) {
            assert(false);
        } catch {}
    }
}
