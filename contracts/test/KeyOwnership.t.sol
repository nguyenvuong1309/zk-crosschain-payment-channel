// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PaymentChannel, IChannelStateVerifier, ILightClientVerifier} from "../src/PaymentChannel.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";

/// @notice Exercises PaymentChannel's EdDSA key-ownership check on its own
///         (docs/threat-model.md assumption #5 fix) — separate from
///         ChannelStateProof.t.sol, which exercises the ZK-proof close path
///         that this check is a prerequisite for.
contract KeyOwnershipTest is Test {
    PaymentChannel channel;
    Groth16Verifier verifier;

    address partyA = address(0xA11CE);
    address partyB = address(0xB0B);

    // Must match circuits/input_gen/build_channel_state_input.js's DEFAULT_PRIV_KEY_A.
    uint256 constant PUBKEY_AX = 6258698228857579243937097735069405513777546488206385948349971781708128047847;
    uint256 constant PUBKEY_AY = 2216124967747932654884761600749314631961003421499958761754620989171020525870;

    function setUp() public {
        verifier = new Groth16Verifier();
        channel = new PaymentChannel(IChannelStateVerifier(address(verifier)), ILightClientVerifier(address(0)));
        vm.deal(partyA, 10 ether);
        vm.deal(partyB, 10 ether);
    }

    function _signOwnership(string memory who, uint256 channelId, address party)
        internal
        returns (uint256 r8x, uint256 r8y, uint256 s)
    {
        // Runs circuits/'s own locally-installed tsx binary directly (see
        // LightClientVerifierBLS.t.sol::_sign for why not "npx tsx").
        string[] memory cmd = new string[](7);
        cmd[0] = "../circuits/node_modules/.bin/tsx";
        cmd[1] = "../circuits/scripts/sign_key_ownership.ts";
        cmd[2] = who;
        cmd[3] = vm.toString(address(channel));
        cmd[4] = vm.toString(block.chainid);
        cmd[5] = vm.toString(channelId);
        cmd[6] = vm.toString(party);

        bytes memory result = vm.ffi(cmd);
        string memory json = string(result);

        r8x = vm.parseJsonUint(json, ".R8x");
        r8y = vm.parseJsonUint(json, ".R8y");
        s = vm.parseJsonUint(json, ".S");
    }

    function test_open_acceptsValidOwnershipSignature() public {
        uint256 channelId = channel.nextChannelId();
        (uint256 r8x, uint256 r8y, uint256 s) = _signOwnership("A", channelId, partyA);

        vm.prank(partyA);
        channel.open{value: 1 ether}(partyB, 1 ether, PUBKEY_AX, PUBKEY_AY, r8x, r8y, s);

        PaymentChannel.Channel memory ch = channel.getChannel(channelId);
        (uint256 pubKeyAx, uint256 pubKeyAy) = (ch.pubKeyAx, ch.pubKeyAy);
        assertEq(pubKeyAx, PUBKEY_AX);
        assertEq(pubKeyAy, PUBKEY_AY);
    }

    function test_open_skipsCheckForZeroPubKey() public {
        // The (0,0) exemption: raw-signature-only channels don't need to
        // register or prove ownership of any EdDSA key.
        vm.prank(partyA);
        channel.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
    }

    function test_open_revertsWhenRegisteringSomeoneElsesKeyWithoutTheirSignature() public {
        // partyA tries to register partyB's real public key, but obviously
        // can't produce partyB's private-key signature over it — the classic
        // attack this fix closes (the key itself is public/observable, e.g.
        // from any prior channel involving partyB).
        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.InvalidKeyOwnershipProof.selector);
        channel.open{value: 1 ether}(partyB, 1 ether, PUBKEY_AX, PUBKEY_AY, 0, 0, 0);
    }

    function test_open_revertsWhenSignatureIsTampered() public {
        uint256 channelId = channel.nextChannelId();
        (uint256 r8x, uint256 r8y, uint256 s) = _signOwnership("A", channelId, partyA);

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.InvalidKeyOwnershipProof.selector);
        channel.open{value: 1 ether}(partyB, 1 ether, PUBKEY_AX, PUBKEY_AY, r8x, r8y, s + 1);
    }

    function test_open_revertsWhenSignatureIsReplayedForADifferentParty() public {
        // A valid signature for partyA opening this exact channelId must not
        // verify for a different caller/channel — the domain binding
        // (channelId, party, address(this), chainid) must actually matter.
        uint256 channelId = channel.nextChannelId();
        (uint256 r8x, uint256 r8y, uint256 s) = _signOwnership("A", channelId, partyA);

        vm.prank(partyB);
        vm.expectRevert(PaymentChannel.InvalidKeyOwnershipProof.selector);
        channel.open{value: 1 ether}(partyA, 1 ether, PUBKEY_AX, PUBKEY_AY, r8x, r8y, s);
    }

    function test_open_revertsWhenPubKeyIsNotOnCurve() public {
        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.InvalidKeyOwnershipProof.selector);
        channel.open{value: 1 ether}(partyB, 1 ether, 123, 456, 0, 0, 0);
    }
}
