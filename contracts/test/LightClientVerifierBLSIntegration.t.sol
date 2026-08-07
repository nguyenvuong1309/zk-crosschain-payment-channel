// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PaymentChannel, IChannelStateVerifier, ILightClientVerifier} from "../src/PaymentChannel.sol";
import {Groth16Verifier} from "../src/Groth16Verifier.sol";
import {LightClientVerifierBLS} from "../src/LightClientVerifierBLS.sol";
import {BabyJubJub} from "../src/BabyJubJub.sol";

/// @notice Proves LightClientVerifierBLS is a genuine drop-in replacement
///         for the original (EdDSA-Poseidon-ZK-proof) LightClientVerifier —
///         both implement the exact `ILightClientVerifier` interface
///         PaymentChannel.sol depends on. `closeWithRemoteAttestation`
///         works completely unchanged, now backed by a real BLS12-381
///         aggregate signature instead of a Groth16 proof.
contract LightClientVerifierBLSIntegrationTest is Test {
    PaymentChannel channelB;
    LightClientVerifierBLS lightClient;

    address partyA = address(0xA11CE);
    address partyB = address(0xB0B);
    uint256 constant REMOTE_CHAIN_ID = 31337;
    address constant REMOTE_CONTRACT = address(0xC0FFEE);

    function setUp() public {
        Groth16Verifier channelStateVerifier = new Groth16Verifier();
        lightClient = new LightClientVerifierBLS();
        channelB = new PaymentChannel(
            IChannelStateVerifier(address(channelStateVerifier)), ILightClientVerifier(address(lightClient))
        );

        vm.deal(partyA, 10 ether);
        vm.deal(partyB, 10 ether);
    }

    function _sign(uint256 chainId, uint256 blockNumber, uint256 stateRoot, uint256 participantBitmap)
        internal
        returns (bytes memory)
    {
        // See LightClientVerifierBLS.t.sol::_sign for why this calls
        // bls-validators' local tsx binary directly instead of "npx tsx".
        string[] memory cmd = new string[](6);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/sign.ts";
        cmd[2] = vm.toString(chainId);
        cmd[3] = vm.toString(blockNumber);
        cmd[4] = vm.toString(stateRoot);
        cmd[5] = vm.toString(participantBitmap);

        bytes memory result = vm.ffi(cmd);
        return vm.parseJsonBytes(string(result), ".aggSig");
    }

    function test_closeWithRemoteAttestation_worksWithRealBLSLightClient() public {
        vm.prank(partyA);
        uint256 channelId = channelB.open{value: 1 ether}(partyB, 1 ether, 0, 0, 0, 0, 0);
        vm.prank(partyB);
        channelB.join{value: 1 ether}(channelId, 0, 0, 0, 0, 0);

        PaymentChannel.ChannelState memory state =
            PaymentChannel.ChannelState({channelId: channelId, nonce: 1, balanceA: 0.5 ether, balanceB: 1.5 ether});

        uint256 stateRoot = uint256(
            keccak256(
                abi.encode(
                    REMOTE_CONTRACT, REMOTE_CHAIN_ID, state.channelId, state.nonce, state.balanceA, state.balanceB
                )
            )
        ) % BabyJubJub.Q;

        uint256 participantBitmap = 0x07; // validators 0,1,2 — real quorum
        bytes memory aggSig = _sign(REMOTE_CHAIN_ID, 1, stateRoot, participantBitmap);
        lightClient.updateState(REMOTE_CHAIN_ID, 1, stateRoot, participantBitmap, aggSig);

        vm.prank(partyA);
        channelB.closeWithRemoteAttestation(channelId, REMOTE_CONTRACT, REMOTE_CHAIN_ID, state);

        (,,,, PaymentChannel.Status status, uint256 nonce, uint256 balA, uint256 balB,,,,,) =
            channelB.channels(channelId);
        assertEq(uint256(status), uint256(PaymentChannel.Status.CHALLENGE_PERIOD));
        assertEq(nonce, 1);
        assertEq(balA, 0.5 ether);
        assertEq(balB, 1.5 ether);
    }
}
