// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PaymentChannel, IChannelStateVerifier, ILightClientVerifier} from "../src/PaymentChannel.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {Groth16VerifierConsensus} from "../src/Groth16VerifierConsensus.sol";
import {LightClientVerifier, IConsensusVerifier} from "../src/LightClientVerifier.sol";
import {BabyJubJub} from "../src/BabyJubJub.sol";

/// @notice Exercises Milestone 3's light client end-to-end within a single
///         Foundry test (two `PaymentChannel` deployments standing in for
///         "Chain A" and "Chain B", same technique
///         PaymentChannelSecurityFixes.t.sol uses for domain-separator
///         tests) — a real consensus_proof.circom proof (via `vm.ffi`)
///         attesting a channel's final state, submitted to
///         LightClientVerifier, then consumed by
///         PaymentChannel.closeWithRemoteAttestation on "Chain B".
contract LightClientTest is Test {
    Groth16Verifier channelStateVerifier;
    Groth16VerifierConsensus consensusVerifier;
    LightClientVerifier lightClient;

    PaymentChannel channelA; // "Chain A" deployment (source of the attestation)
    PaymentChannel channelB; // "Chain B" deployment (consumes it)

    address partyA = address(0xA11CE);
    address partyB = address(0xB0B);

    uint256 constant REMOTE_CHAIN_ID = 31337; // stands in for "Chain A"'s chainid

    function setUp() public {
        channelStateVerifier = new Groth16Verifier();
        consensusVerifier = new Groth16VerifierConsensus();
        lightClient = new LightClientVerifier(IConsensusVerifier(address(consensusVerifier)));

        // "Chain A": no light client needed, it's the attestation source.
        channelA =
            new PaymentChannel(IChannelStateVerifier(address(channelStateVerifier)), ILightClientVerifier(address(0)));
        // "Chain B": configured to trust `lightClient`.
        channelB = new PaymentChannel(
            IChannelStateVerifier(address(channelStateVerifier)), ILightClientVerifier(address(lightClient))
        );

        vm.deal(partyA, 10 ether);
        vm.deal(partyB, 10 ether);
    }

    function _generateConsensusProof(uint256 chainId, uint256 blockNumber, uint256 stateRoot)
        internal
        returns (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[13] memory pubSignals)
    {
        string[] memory cmd = new string[](5);
        cmd[0] = "bash";
        cmd[1] = "../circuits/scripts/prove_and_export_consensus.sh";
        cmd[2] = vm.toString(chainId);
        cmd[3] = vm.toString(blockNumber);
        cmd[4] = vm.toString(stateRoot);

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
        for (uint256 i = 0; i < 13; i++) {
            pubSignals[i] = pubArr[i];
        }
    }

    /// @dev The exact formula PaymentChannel.closeWithRemoteAttestation checks —
    ///      see its doc comment.
    function _remoteStateHash(address remoteContract, uint256 remoteChainId, PaymentChannel.ChannelState memory state)
        internal
        pure
        returns (uint256)
    {
        return uint256(
            keccak256(
            abi.encode(remoteContract, remoteChainId, state.channelId, state.nonce, state.balanceA, state.balanceB)
        )
        ) % BabyJubJub.Q;
    }

    function test_updateState_acceptsRealQuorumProof() public {
        uint256 stateRoot = 12345;
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[13] memory pubSignals) =
            _generateConsensusProof(REMOTE_CHAIN_ID, 1, stateRoot);

        lightClient.updateState(a, b, c, pubSignals);

        assertEq(lightClient.trustedStateRoot(REMOTE_CHAIN_ID), stateRoot);
        assertEq(lightClient.trustedBlockNumber(REMOTE_CHAIN_ID), 1);
    }

    function test_updateState_revertsOnStaleBlockNumber() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[13] memory pubSignals) =
            _generateConsensusProof(REMOTE_CHAIN_ID, 5, 999);
        lightClient.updateState(a, b, c, pubSignals);

        (uint256[2] memory a2, uint256[2][2] memory b2, uint256[2] memory c2, uint256[13] memory pubSignals2) =
            _generateConsensusProof(REMOTE_CHAIN_ID, 5, 1000); // same blockNumber, different stateRoot
        vm.expectRevert(LightClientVerifier.StaleBlockNumber.selector);
        lightClient.updateState(a2, b2, c2, pubSignals2);
    }

    function test_updateState_revertsOnUnknownCommittee() public {
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[13] memory pubSignals) =
            _generateConsensusProof(REMOTE_CHAIN_ID, 1, 42);
        pubSignals[3] = pubSignals[3] + 1; // tamper with a validator pubkey

        vm.expectRevert(LightClientVerifier.UnknownValidatorCommittee.selector);
        lightClient.updateState(a, b, c, pubSignals);
    }

    function test_closeWithRemoteAttestation_revertsWhenLightClientNotConfigured() public {
        // channelA has no light client configured (address(0)).
        vm.prank(partyA);
        uint256 channelId = channelA.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channelA.join{value: 1 ether}(channelId, 0, 0, 0, 0, 0);

        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: channelId, nonce: 1, balanceA: 0.5 ether, balanceB: 1.5 ether});

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.LightClientNotConfigured.selector);
        channelA.closeWithRemoteAttestation(channelId, address(0xCAFE), REMOTE_CHAIN_ID, state);
    }

    function test_closeWithRemoteAttestation_revertsWithoutMatchingAttestation() public {
        vm.prank(partyA);
        uint256 channelId = channelB.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channelB.join{value: 1 ether}(channelId, 0, 0, 0, 0, 0);

        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: channelId, nonce: 1, balanceA: 0.5 ether, balanceB: 1.5 ether});

        vm.prank(partyA);
        vm.expectRevert(PaymentChannel.UntrustedRemoteState.selector);
        channelB.closeWithRemoteAttestation(channelId, address(channelA), REMOTE_CHAIN_ID, state);
    }

    /// @notice The full Milestone 3 flow: a channel's final state on "Chain A"
    ///         gets validator-attested and settled on "Chain B" with the exact
    ///         same balances, via LightClientVerifier — no real bridge.
    function test_closeWithRemoteAttestation_settlesUsingAttestedRemoteState() public {
        vm.prank(partyA);
        uint256 channelId = channelB.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channelB.join{value: 1 ether}(channelId, 0, 0, 0, 0, 0);

        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: channelId, nonce: 1, balanceA: 0.5 ether, balanceB: 1.5 ether});

        uint256 stateRoot = _remoteStateHash(address(channelA), REMOTE_CHAIN_ID, state);
        (uint256[2] memory a, uint256[2][2] memory b, uint256[2] memory c, uint256[13] memory pubSignals) =
            _generateConsensusProof(REMOTE_CHAIN_ID, 1, stateRoot);
        lightClient.updateState(a, b, c, pubSignals);

        vm.prank(partyA);
        channelB.closeWithRemoteAttestation(channelId, address(channelA), REMOTE_CHAIN_ID, state);

        PaymentChannel.Channel memory ch = channelB.getChannel(channelId);
        assertEq(uint256(ch.status), uint256(PaymentChannel.Status.CHALLENGE_PERIOD));
        assertEq(ch.nonce, 1);
        assertEq(ch.balanceA, 0.5 ether);
        assertEq(ch.balanceB, 1.5 ether);

        vm.warp(block.timestamp + channelB.CHALLENGE_PERIOD() + 1);
        uint256 balABefore = partyA.balance;
        uint256 balBBefore = partyB.balance;

        vm.prank(partyB);
        channelB.withdraw(channelId);

        assertEq(partyA.balance, balABefore + 0.5 ether);
        assertEq(partyB.balance, balBBefore + 1.5 ether);
    }
}
