// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {LightClientVerifierBLSGeneral} from "../src/LightClientVerifierBLSGeneral.sol";

/// @notice Milestone 5 step 3 (see PLAN.md) — exercises
///         LightClientVerifierBLSGeneral.sol at REAL Ethereum sync-committee
///         scale (512 validators, 342-of-512 threshold = ceil(2*512/3),
///         matching the actual spec constant), using a real demo committee
///         from `bls-validators/generate_keys_general.ts` and real
///         aggregate signatures from `bls-validators/sign_general.ts` (both
///         via `vm.ffi`, same pattern as LightClientVerifierBLS.t.sol).
///
///         Run `npx tsx generate_keys_general.ts 512` in bls-validators/
///         first (writes keys_general_512.json, committed to git — see that
///         file) if it's missing.
contract LightClientVerifierBLSGeneralTest is Test {
    LightClientVerifierBLSGeneral lightClient;

    uint256 constant CHAIN_ID = 31337;
    uint256 constant NUM_VALIDATORS = 512;
    uint256 constant EXPECTED_THRESHOLD = 342; // ceil(2*512/3) — matches Ethereum's real sync committee quorum
    uint256 constant BATCH_SIZE = 64;

    string constant KEYS_PATH = "../bls-validators/keys_general_512.json";

    function setUp() public {
        lightClient = new LightClientVerifierBLSGeneral();

        bytes[] memory pubkeys = _loadPubkeys();
        assertEq(pubkeys.length, NUM_VALIDATORS, "keys_general_512.json doesn't have 512 validators");

        uint256 totalGas = 0;
        for (uint256 offset = 0; offset < pubkeys.length; offset += BATCH_SIZE) {
            uint256 end = offset + BATCH_SIZE > pubkeys.length ? pubkeys.length : offset + BATCH_SIZE;
            bytes[] memory batch = new bytes[](end - offset);
            for (uint256 i = offset; i < end; i++) {
                batch[i - offset] = pubkeys[i];
            }
            uint256 gasBefore = gasleft();
            lightClient.addValidators(batch);
            uint256 gasUsed = gasBefore - gasleft();
            totalGas += gasUsed;
            console2.log("addValidators batch gas:", gasUsed);
        }
        console2.log("addValidators TOTAL gas (all 512, 8 batches of 64):", totalGas);

        uint256 gasBeforeFinalize = gasleft();
        lightClient.finalize();
        console2.log("finalize() gas:", gasBeforeFinalize - gasleft());

        assertEq(lightClient.numValidators(), NUM_VALIDATORS);
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
        cmd[1] = "../bls-validators/sign_general.ts";
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

    function test_updateState_acceptsExactThreshold() public {
        (bytes memory aggSig, bytes memory bitmap) = _sign(CHAIN_ID, 1, 12345, EXPECTED_THRESHOLD);

        uint256 gasBefore = gasleft();
        lightClient.updateState(CHAIN_ID, 1, 12345, bitmap, aggSig);
        console2.log("updateState gas (342-of-512 quorum):", gasBefore - gasleft());

        assertEq(lightClient.trustedStateRoot(CHAIN_ID), 12345);
        assertEq(lightClient.trustedBlockNumber(CHAIN_ID), 1);
    }

    function test_updateState_revertsBelowThreshold() public {
        (bytes memory aggSig, bytes memory bitmap) = _sign(CHAIN_ID, 1, 12345, EXPECTED_THRESHOLD - 1);

        vm.expectRevert(LightClientVerifierBLSGeneral.InsufficientQuorum.selector);
        lightClient.updateState(CHAIN_ID, 1, 12345, bitmap, aggSig);
    }

    function test_updateState_acceptsFullCommittee() public {
        (bytes memory aggSig, bytes memory bitmap) = _sign(CHAIN_ID, 1, 777, NUM_VALIDATORS);

        uint256 gasBefore = gasleft();
        lightClient.updateState(CHAIN_ID, 1, 777, bitmap, aggSig);
        console2.log("updateState gas (512-of-512, full committee):", gasBefore - gasleft());

        assertEq(lightClient.trustedStateRoot(CHAIN_ID), 777);
    }

    function test_updateState_revertsOnStaleBlockNumber() public {
        (bytes memory aggSig1, bytes memory bitmap) = _sign(CHAIN_ID, 5, 111, EXPECTED_THRESHOLD);
        lightClient.updateState(CHAIN_ID, 5, 111, bitmap, aggSig1);

        (bytes memory aggSig2, bytes memory bitmap2) = _sign(CHAIN_ID, 5, 222, EXPECTED_THRESHOLD);
        vm.expectRevert(LightClientVerifierBLSGeneral.StaleBlockNumber.selector);
        lightClient.updateState(CHAIN_ID, 5, 222, bitmap2, aggSig2);
    }

    function test_updateState_revertsOnBitmapLengthMismatch() public {
        bytes memory wrongLengthBitmap = new bytes(63); // committee needs ceil(512/8) = 64 bytes
        vm.expectRevert(LightClientVerifierBLSGeneral.BitmapLengthMismatch.selector);
        lightClient.updateState(CHAIN_ID, 1, 12345, wrongLengthBitmap, new bytes(256));
    }

    function test_addValidators_revertsAfterFinalize() public {
        bytes[] memory empty = new bytes[](0);
        vm.expectRevert(LightClientVerifierBLSGeneral.AlreadyFinalized.selector);
        lightClient.addValidators(empty);
    }

    function test_addValidators_revertsFromNonDeployer() public {
        bytes[] memory empty = new bytes[](0);
        // setUp() already finalized, so this would hit AlreadyFinalized
        // first from the deployer — deploy a fresh, non-finalized instance
        // to isolate the onlyDeployer check.
        LightClientVerifierBLSGeneral fresh = new LightClientVerifierBLSGeneral();
        vm.prank(address(0xBEEF));
        vm.expectRevert(LightClientVerifierBLSGeneral.NotDeployer.selector);
        fresh.addValidators(empty);
    }
}
