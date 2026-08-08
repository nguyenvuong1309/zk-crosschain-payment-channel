// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PaymentChannel, IChannelStateVerifier, ILightClientVerifier} from "../src/PaymentChannel.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

/// @notice Exercises PaymentChannel.closeWithProof() with a REAL Groth16
///         proof generated end-to-end from circuits/circuits/channel_state.circom.
///
///         Unlike an earlier version of this test, the proof is NOT
///         hardcoded: since the domain-separator fix (see docs/threat-model.md,
///         "Lỗi đã tìm và sửa" #D) binds every proof to the specific
///         `address(this)`/`block.chainid` of the PaymentChannel it targets,
///         a hardcoded proof would only work for one specific deployment
///         address — fragile and not actually proving the domain check
///         works. Instead, `_generateProof` shells out (via `vm.ffi`, see
///         foundry.toml) to circuits/scripts/prove_and_export.sh, which
///         generates a fresh proof bound to whatever address Forge actually
///         deployed `channel` at in THIS test run. Requires `circuits/`
///         dependencies installed and the circuit built — see circuits/README
///         or PLAN.md Milestone 2 for the one-time setup.
///
///         Public signal layout (see IChannelStateVerifier / PaymentChannel.sol):
///           [0] outNonce  [1] startCommitment  [2] endCommitment
///           [3] channelId [4] pubKeyAx  [5] pubKeyAy  [6] pubKeyBx  [7] pubKeyBy
///           [8] contractAddress  [9] chainId  [10] startNonce
///
///         Since the "privacy upgrade" (see channel_state.circom's doc
///         comment), the proof never exposes balances directly — only
///         Poseidon commitments to them, at BOTH ends of the chain (needed
///         for chaining proofs together — see the "chaining" tests below).
///         Tests that need the actual balances (e.g. to assert a payout)
///         use the known demo values baked into
///         circuits/input_gen/build_channel_state_input.ts's DEFAULT_UPDATES/
///         DEFAULT_BLINDING and open via `withdrawWithOpening`.
contract ChannelStateProofTest is Test {
    PaymentChannel channel;
    Groth16Verifier verifier;

    address partyA = address(0xA11CE);
    address partyB = address(0xB0B);

    // Must exactly match the EdDSA keys `build_channel_state_input.ts`
    // signs with by default (DEFAULT_PRIV_KEY_A/B) — recomputed here once,
    // see circuits/input_gen/build_channel_state_input.ts.
    uint256 constant PUBKEY_AX = 6258698228857579243937097735069405513777546488206385948349971781708128047847;
    uint256 constant PUBKEY_AY = 2216124967747932654884761600749314631961003421499958761754620989171020525870;
    uint256 constant PUBKEY_BX = 21036738825193802266623779881692904721121294284483365787352024792419651640674;
    uint256 constant PUBKEY_BY = 17088268747125489648041885901336523179405935374090472533134592214513880559267;

    uint256 constant DEPOSIT_A = 1_000_000; // wei — must match build_channel_state_input.ts's defaults
    uint256 constant DEPOSIT_B = 1_000_000;

    // Final state reached by DEFAULT_UPDATES in build_channel_state_input.ts.
    uint256 constant FINAL_BALANCE_A = 400_000;
    uint256 constant FINAL_BALANCE_B = 1_600_000;
    // DEFAULT_BLINDING in build_channel_state_input.ts.
    uint256 constant DEFAULT_BLINDING = 424242424242424242;

    function setUp() public {
        verifier = new Groth16Verifier();
        channel = new PaymentChannel(IChannelStateVerifier(address(verifier)), ILightClientVerifier(address(0)));
        vm.deal(partyA, 10 ether);
        vm.deal(partyB, 10 ether);
    }

    /// @dev Shells out to circuits/scripts/sign_key_ownership.ts (via `vm.ffi`)
    ///      for a real Schnorr key-ownership signature over the demo's known
    ///      EdDSA private key A or B, bound to `channel`'s actual deployed
    ///      address/chainid/channelId/party — required by open()/join() now
    ///      that `_verifyKeyOwnership` checks it (docs/threat-model.md #5 fix).
    function _signOwnership(string memory who, uint256 channelId, address party)
        internal
        returns (uint256 r8x, uint256 r8y, uint256 s)
    {
        // Runs circuits/'s own locally-installed tsx binary directly (see
        // LightClientVerifierBLS.t.sol::_sign for why not "npx tsx").
        string[] memory cmd = new string[](6);
        cmd[0] = "../circuits/node_modules/.bin/tsx";
        cmd[1] = "../circuits/scripts/sign_key_ownership.ts";
        cmd[2] = who;
        cmd[3] = vm.toString(address(channel));
        cmd[4] = vm.toString(block.chainid);
        cmd[5] = vm.toString(channelId);
        // sign_key_ownership.ts's 5th positional arg is the party address;
        // vm.ffi has no fixed-length limit, so just size the array for it.
        string[] memory cmdWithParty = new string[](7);
        for (uint256 i = 0; i < 6; i++) {
            cmdWithParty[i] = cmd[i];
        }
        cmdWithParty[6] = vm.toString(party);

        bytes memory result = vm.ffi(cmdWithParty);
        string memory json = string(result);

        r8x = vm.parseJsonUint(json, ".R8x");
        r8y = vm.parseJsonUint(json, ".R8y");
        s = vm.parseJsonUint(json, ".S");
    }

    /// @dev Opens a throwaway channel first so the real one lands on
    ///      channelId == 1, matching what circuits/input_gen always proves
    ///      for (kept from the original version of this test — channelId
    ///      itself doesn't need to be dynamic, only the contract address).
    function _openRealChannel() internal returns (uint256 channelId) {
        vm.prank(partyA);
        channel.open{value: 1}(partyB, 1, 0, 0, 0, 0, 0); // channelId 0, discarded

        channelId = channel.nextChannelId(); // == 1, the id the next open() below will assign
        assertEq(channelId, 1);

        (uint256 aR8x, uint256 aR8y, uint256 aS) = _signOwnership("A", channelId, partyA);
        vm.prank(partyA);
        channelId = channel.open{value: DEPOSIT_A}(partyB, DEPOSIT_A, PUBKEY_AX, PUBKEY_AY, aR8x, aR8y, aS);

        (uint256 bR8x, uint256 bR8y, uint256 bS) = _signOwnership("B", channelId, partyB);
        vm.prank(partyB);
        channel.join{value: DEPOSIT_B}(channelId, PUBKEY_BX, PUBKEY_BY, bR8x, bR8y, bS);
    }

    /// @dev Generates a GENESIS-anchored real proof (startNonce=0,
    ///      startBalance=deposits) bound to `channel`'s actual deployed
    ///      address and the current `block.chainid`, via
    ///      circuits/scripts/prove_and_export.sh (~5-10s). For a
    ///      CONTINUATION proof (chaining past `steps` updates), build the
    ///      `cmd` array directly and call `_runProveScript` — see the
    ///      chaining tests below, which use
    ///      circuits/scripts/prove_and_export_continuation.sh instead.
    function _generateProof(uint256 channelId)
        internal
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "bash";
        cmd[1] = "../circuits/scripts/prove_and_export.sh";
        cmd[2] = vm.toString(address(channel));
        cmd[3] = vm.toString(block.chainid);
        cmd[4] = vm.toString(channelId);
        return _runProveScript(cmd);
    }

    function _runProveScript(string[] memory cmd)
        internal
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals)
    {
        bytes memory result = vm.ffi(cmd);
        string memory json = string(result);

        uint256[] memory aArr = vm.parseJsonUintArray(json, ".a");
        uint256[] memory b0Arr = vm.parseJsonUintArray(json, ".b0");
        uint256[] memory b1Arr = vm.parseJsonUintArray(json, ".b1");
        uint256[] memory cArr = vm.parseJsonUintArray(json, ".c");
        uint256[] memory pubArr = vm.parseJsonUintArray(json, ".pubSignals");

        a = [aArr[0], aArr[1]];
        b = [[b0Arr[0], b0Arr[1]], [b1Arr[0], b1Arr[1]]];
        c = [cArr[0], cArr[1]];
        for (uint256 i = 0; i < 11; i++) {
            pubSignals[i] = pubArr[i];
        }
    }

    function test_verifierAcceptsRealProof_boundToActualDeployedAddress() public {
        uint256 channelId = _openRealChannel();
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals) =
            _generateProof(channelId);

        assertTrue(verifier.verifyProof(a, b, c, pubSignals));
        assertEq(
            pubSignals[8], uint256(uint160(address(channel))), "proof's contractAddress must match actual deployment"
        );
        assertEq(pubSignals[9], block.chainid, "proof's chainId must match actual chain");
        assertEq(pubSignals[10], 0, "genesis-anchored proof must start at nonce 0");
    }

    function test_closeWithProof_startsChallengePeriodWithCommitment() public {
        uint256 channelId = _openRealChannel();
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals) =
            _generateProof(channelId);

        vm.prank(partyA);
        channel.closeWithProof(channelId, a, b, c, pubSignals);

        PaymentChannel.Channel memory ch = channel.getChannel(channelId);
        assertEq(uint256(ch.status), uint256(PaymentChannel.Status.CHALLENGE_PERIOD));
        assertEq(ch.nonce, 6);
        assertTrue(ch.balancesCommitted, "closeWithProof must not reveal the balances directly");
        assertEq(ch.balanceCommitment, pubSignals[2], "stored commitment must be the proof's endCommitment");
    }

    function test_closeWithProof_thenWithdrawWithOpening_paysOutProvenBalances() public {
        uint256 channelId = _openRealChannel();
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals) =
            _generateProof(channelId);

        vm.prank(partyA);
        channel.closeWithProof(channelId, a, b, c, pubSignals);

        vm.warp(block.timestamp + channel.CHALLENGE_PERIOD() + 1);

        // Plain withdraw() must refuse — the balances are only committed to,
        // not revealed, at this point.
        vm.prank(partyB);
        vm.expectRevert(PaymentChannel.BalancesNotYetRevealed.selector);
        channel.withdraw(channelId);

        uint256 balABefore = partyA.balance;
        uint256 balBBefore = partyB.balance;

        vm.prank(partyB);
        channel.withdrawWithOpening(channelId, FINAL_BALANCE_A, FINAL_BALANCE_B, DEFAULT_BLINDING);

        assertEq(partyA.balance, balABefore + FINAL_BALANCE_A);
        assertEq(partyB.balance, balBBefore + FINAL_BALANCE_B);
    }

    function test_withdrawWithOpening_revertsOnWrongOpening() public {
        uint256 channelId = _openRealChannel();
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals) =
            _generateProof(channelId);

        vm.prank(partyA);
        channel.closeWithProof(channelId, a, b, c, pubSignals);
        vm.warp(block.timestamp + channel.CHALLENGE_PERIOD() + 1);

        vm.prank(partyB);
        vm.expectRevert(PaymentChannel.CommitmentMismatch.selector);
        // Right total, wrong split — conservation passes but the opening
        // doesn't match the committed value, so this must still revert.
        channel.withdrawWithOpening(channelId, FINAL_BALANCE_A + 1, FINAL_BALANCE_B - 1, DEFAULT_BLINDING);
    }

    function test_closeWithProof_revertsOnWrongChannelId() public {
        uint256 channelId = _openRealChannel();
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals) =
            _generateProof(channelId);

        pubSignals[3] = channelId + 999; // tamper with the channelId public signal

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.ChannelIdMismatch.selector);
        channel.closeWithProof(channelId, a, b, c, pubSignals);
    }

    function test_closeWithProof_revertsOnPublicKeyMismatch() public {
        // Open a channel with the (0,0) "no EdDSA key" exemption — DIFFERENT
        // from the real keys baked into the proof below, which is exactly
        // what this test wants to exercise (999/888 would need a real
        // ownership signature too now; 0/0 sidesteps that while keeping the
        // actual assertion, a pubSignals-vs-registered-key mismatch, intact).
        vm.prank(partyA);
        uint256 channelId = channel.open{value: DEPOSIT_A}(partyB, DEPOSIT_A, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channel.join{value: DEPOSIT_B}(channelId, 0, 0, 0, 0, 0);

        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals) =
            _generateProof(channelId);
        pubSignals[3] = channelId;

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.PublicKeyMismatch.selector);
        channel.closeWithProof(channelId, a, b, c, pubSignals);
    }

    function test_closeWithProof_revertsOnTamperedProof() public {
        uint256 channelId = _openRealChannel();
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals) =
            _generateProof(channelId);

        pubSignals[2] = 999_999; // claim a different endCommitment without a matching proof

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.InvalidProof.selector);
        channel.closeWithProof(channelId, a, b, c, pubSignals);
    }

    function test_closeWithProof_revertsOnWrongAnchor() public {
        uint256 channelId = _openRealChannel();
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals) =
            _generateProof(channelId);

        // Claim a non-zero startNonce for a channel that's never been
        // proof-closed before (ch.balancesCommitted is false) — must be
        // rejected BEFORE ever calling the (expensive) Groth16 verifier,
        // since it can't possibly match the required genesis anchor.
        pubSignals[10] = 1;

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.InvalidChainAnchor.selector);
        channel.closeWithProof(channelId, a, b, c, pubSignals);
    }

    /// @notice The domain-separator fix itself: a proof generated for a
    ///         DIFFERENT contract address (standing in for "the same
    ///         channelId on Chain B") must be rejected here, even with
    ///         matching channelId/keys/deposits.
    function test_closeWithProof_revertsWhenProofBoundToADifferentDeployment() public {
        uint256 channelId = _openRealChannel();

        // Generate a proof bound to a DIFFERENT, unrelated address instead
        // of the real `channel` address.
        address fakeChainBAddress = address(0xB00B1E5);
        string[] memory cmd = new string[](5);
        cmd[0] = "bash";
        cmd[1] = "../circuits/scripts/prove_and_export.sh";
        cmd[2] = vm.toString(fakeChainBAddress);
        cmd[3] = vm.toString(block.chainid);
        cmd[4] = vm.toString(channelId);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[11] memory pubSignals) =
            _runProveScript(cmd);

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.DomainMismatch.selector);
        channel.closeWithProof(channelId, a, b, c, pubSignals);
    }

    // -------------------------------------------------------------------
    // Chaining: a channel's off-chain history spans MORE than one proof's
    // worth of updates (`steps` = 4 per proof, see channel_state.circom).
    // A second proof continues from the first's committed final state
    // instead of re-proving the whole history from genesis — see
    // _verifyChannelProof's doc comment and channel_state.circom's
    // "Chaining" section.
    // -------------------------------------------------------------------

    function test_challengeWithProof_chainsFromPriorCommitment_pastFourUpdates() public {
        uint256 channelId = _openRealChannel();

        // Proof 1: genesis-anchored, 4 updates (nonces 1,2,5,6 — the
        // circuits/ DEFAULT_UPDATES fixture), ending at (400_000, 1_600_000).
        (uint256[2] memory a1, uint256[2][2] memory b1, uint256[2] memory c1, uint256[11] memory pub1) =
            _generateProof(channelId);
        vm.prank(partyA);
        channel.closeWithProof(channelId, a1, b1, c1, pub1);

        PaymentChannel.Channel memory chAfter1 = channel.getChannel(channelId);
        assertEq(chAfter1.nonce, 6);
        assertTrue(chAfter1.balancesCommitted);

        // Proof 2: CONTINUES from proof 1's committed end state — 4 MORE
        // updates (nonces 7,8,9,10) that a single `steps=4` proof could
        // never have covered together with proof 1's 4 in one shot. Real
        // Groth16 proof, generated via a second, independent FFI call with
        // explicit --start-* / --updates overrides (see
        // scripts/build_ffi_input_continuation.ts).
        string[] memory cmd = new string[](5);
        cmd[0] = "bash";
        cmd[1] = "../circuits/scripts/prove_and_export_continuation.sh";
        cmd[2] = vm.toString(address(channel));
        cmd[3] = vm.toString(block.chainid);
        cmd[4] = vm.toString(channelId);
        (uint256[2] memory a2, uint256[2][2] memory b2, uint256[2] memory c2, uint256[11] memory pub2) =
            _runProveScript(cmd);

        // The continuation proof's startNonce/startCommitment must exactly
        // match proof 1's outNonce/endCommitment — the on-chain link.
        assertEq(pub2[10], chAfter1.nonce, "continuation proof's startNonce must match proof 1's outNonce");
        assertEq(
            pub2[1],
            chAfter1.balanceCommitment,
            "continuation proof's startCommitment must match proof 1's endCommitment"
        );

        vm.prank(partyB);
        channel.challengeWithProof(channelId, a2, b2, c2, pub2);

        PaymentChannel.Channel memory chAfter2 = channel.getChannel(channelId);
        assertEq(chAfter2.nonce, 10, "chained proof must advance past what proof 1 alone could reach");
        assertTrue(chAfter2.balancesCommitted);
        assertEq(chAfter2.balanceCommitment, pub2[2]);

        // Settle: withdraw using the SECOND proof's opening (100_000/1_900_000
        // — see scripts/build_ffi_input_continuation.ts's fixture).
        vm.warp(block.timestamp + channel.CHALLENGE_PERIOD() + 1);
        uint256 balABefore = partyA.balance;
        uint256 balBBefore = partyB.balance;
        vm.prank(partyA);
        channel.withdrawWithOpening(channelId, 100_000, 1_900_000, DEFAULT_BLINDING);
        assertEq(partyA.balance, balABefore + 100_000);
        assertEq(partyB.balance, balBBefore + 1_900_000);
    }

    /// @notice A continuation proof claiming a DIFFERENT (wrong) start
    ///         commitment than the channel's actual stored one must be
    ///         rejected — otherwise chaining would let anyone splice in an
    ///         arbitrary alternate history at the join point.
    function test_challengeWithProof_revertsOnWrongContinuationAnchor() public {
        uint256 channelId = _openRealChannel();
        (uint256[2] memory a1, uint256[2][2] memory b1, uint256[2] memory c1, uint256[11] memory pub1) =
            _generateProof(channelId);
        vm.prank(partyA);
        channel.closeWithProof(channelId, a1, b1, c1, pub1);

        string[] memory cmd = new string[](5);
        cmd[0] = "bash";
        cmd[1] = "../circuits/scripts/prove_and_export_continuation.sh";
        cmd[2] = vm.toString(address(channel));
        cmd[3] = vm.toString(block.chainid);
        cmd[4] = vm.toString(channelId);
        (uint256[2] memory a2, uint256[2][2] memory b2, uint256[2] memory c2, uint256[11] memory pub2) =
            _runProveScript(cmd);

        pub2[1] = pub2[1] + 1; // tamper with startCommitment — no longer matches proof 1's endCommitment

        vm.prank(partyB);
        vm.expectRevert(PaymentChannel.InvalidChainAnchor.selector);
        channel.challengeWithProof(channelId, a2, b2, c2, pub2);
    }
}
