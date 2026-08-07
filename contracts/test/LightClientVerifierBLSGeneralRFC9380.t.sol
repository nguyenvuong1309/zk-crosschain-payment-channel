// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {LightClientVerifierBLSGeneralRFC9380} from "../src/LightClientVerifierBLSGeneralRFC9380.sol";

/// @notice Milestone 5 (see PLAN.md) — the final integration: `updateState()`
///         itself (not just RFC9380.sol/BLS12381.sol called directly, as in
///         LightClientVerifierBLSReal.t.sol) now verifies signatures using
///         the real RFC9380 hash-to-curve. Uses the same 512-key demo
///         committee as LightClientVerifierBLSGeneral.t.sol (not real
///         mainnet keys — this tests the PROTOCOL/contract logic, real-data
///         integration was already proven separately in
///         LightClientVerifierBLSReal.t.sol) signed via
///         bls-validators/sign_general_rfc9380.ts instead of sign_general.ts.
contract LightClientVerifierBLSGeneralRFC9380Test is Test {
    LightClientVerifierBLSGeneralRFC9380 lightClient;

    uint256 constant CHAIN_ID = 31337;
    uint256 constant NUM_VALIDATORS = 512;
    uint256 constant EXPECTED_THRESHOLD = 342;
    uint256 constant BATCH_SIZE = 64;

    string constant KEYS_PATH = "../bls-validators/keys_general_512.json";

    function setUp() public {
        lightClient = new LightClientVerifierBLSGeneralRFC9380();

        bytes[] memory pubkeys = _loadPubkeys();
        assertEq(pubkeys.length, NUM_VALIDATORS);

        for (uint256 offset = 0; offset < pubkeys.length; offset += BATCH_SIZE) {
            uint256 end = offset + BATCH_SIZE > pubkeys.length ? pubkeys.length : offset + BATCH_SIZE;
            bytes[] memory batch = new bytes[](end - offset);
            for (uint256 i = offset; i < end; i++) {
                batch[i - offset] = pubkeys[i];
            }
            lightClient.addValidators(batch);
        }
        lightClient.finalize();
        assertEq(lightClient.threshold(), EXPECTED_THRESHOLD);
    }

    function _loadPubkeys() internal returns (bytes[] memory) {
        string[] memory cmd = new string[](3);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/dump_pubkeys.ts";
        cmd[2] = KEYS_PATH;
        bytes memory result = vm.ffi(cmd);
        return vm.parseJsonBytesArray(string(result), ".pubkeys");
    }

    function _sign(uint256 chainId, uint256 blockNumber, uint256 stateRoot, uint256 participantCount)
        internal
        returns (bytes memory aggSig, bytes memory participantBitmap)
    {
        string[] memory cmd = new string[](7);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/sign_general_rfc9380.ts";
        cmd[2] = KEYS_PATH;
        cmd[3] = vm.toString(chainId);
        cmd[4] = vm.toString(blockNumber);
        cmd[5] = vm.toString(stateRoot);
        cmd[6] = vm.toString(participantCount);

        bytes memory result = vm.ffi(cmd);
        string memory json = string(result);
        aggSig = vm.parseJsonBytes(json, ".aggSig");
        participantBitmap = vm.parseJsonBytes(json, ".participantBitmap");
    }

    /// @notice The main deliverable: updateState() itself, end to end, using
    ///         real RFC9380 hash-to-curve — not a demo/simplified scheme.
    function test_updateState_acceptsRealRFC9380Signature() public {
        (bytes memory aggSig, bytes memory bitmap) = _sign(CHAIN_ID, 1, 12345, EXPECTED_THRESHOLD);

        uint256 gasBefore = gasleft();
        lightClient.updateState(CHAIN_ID, 1, 12345, bitmap, aggSig);
        console2.log("updateState gas (RFC9380, 342-of-512 quorum):", gasBefore - gasleft());

        assertEq(lightClient.trustedStateRoot(CHAIN_ID), 12345);
        assertEq(lightClient.trustedBlockNumber(CHAIN_ID), 1);
    }

    function test_updateState_revertsBelowThreshold() public {
        (bytes memory aggSig, bytes memory bitmap) = _sign(CHAIN_ID, 1, 12345, EXPECTED_THRESHOLD - 1);
        vm.expectRevert(LightClientVerifierBLSGeneralRFC9380.InsufficientQuorum.selector);
        lightClient.updateState(CHAIN_ID, 1, 12345, bitmap, aggSig);
    }

    function test_updateState_revertsOnTamperedStateRoot() public {
        (bytes memory aggSig, bytes memory bitmap) = _sign(CHAIN_ID, 1, 12345, EXPECTED_THRESHOLD);
        vm.expectRevert(LightClientVerifierBLSGeneralRFC9380.InvalidAggregateSignature.selector);
        lightClient.updateState(CHAIN_ID, 1, 99999, bitmap, aggSig);
    }

    /// @notice Proves the two schemes are genuinely NOT interchangeable — a
    ///         signature made with the OLD simplified scheme
    ///         (sign_general.ts) must be REJECTED here, since this contract
    ///         hashes the message to a different curve point than
    ///         LightClientVerifierBLSGeneral.sol does for the same input.
    function test_updateState_rejectsSignatureFromOldSimplifiedScheme() public {
        string[] memory cmd = new string[](7);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/sign_general.ts"; // OLD scheme, not sign_general_rfc9380.ts
        cmd[2] = KEYS_PATH;
        cmd[3] = vm.toString(CHAIN_ID);
        cmd[4] = "1";
        cmd[5] = "12345";
        cmd[6] = vm.toString(EXPECTED_THRESHOLD);
        bytes memory result = vm.ffi(cmd);
        string memory json = string(result);
        bytes memory oldSchemeSig = vm.parseJsonBytes(json, ".aggSig");
        bytes memory bitmap = vm.parseJsonBytes(json, ".participantBitmap");

        vm.expectRevert(LightClientVerifierBLSGeneralRFC9380.InvalidAggregateSignature.selector);
        lightClient.updateState(CHAIN_ID, 1, 12345, bitmap, oldSchemeSig);
    }
}
