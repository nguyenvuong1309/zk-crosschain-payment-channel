// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {LightClientVerifierBLSGeneral} from "../src/LightClientVerifierBLSGeneral.sol";
import {SSZ} from "../src/SSZ.sol";

/// @notice Milestone 5 step 6 (see PLAN.md) — wires the REAL data captured
///         by `bls-validators/capture_real_snapshot.ts` (Ethereum mainnet's
///         actual 512-validator sync committee, its merkle inclusion proof,
///         and a real aggregate BLS signature) into the contracts built in
///         earlier Milestone 5 steps, against a FROZEN fixture
///         (`bls-validators/real_sync_committee_snapshot.json`) instead of a
///         live beacon API call — reproducible in CI, not flaky against a
///         constantly-advancing chain.
///
///         What this proves ON-CHAIN, with real data:
///           1. The real 512-key committee registers into
///              `LightClientVerifierBLSGeneral` exactly like the synthetic
///              demo committee does (same `addValidators`/`finalize` flow,
///              same gas order of magnitude — confirms step 3's gas numbers
///              weren't an artifact of using self-derived keys).
///           2. `SSZ.sol`'s merkle-branch check accepts the REAL
///              `current_sync_committee_branch` against the REAL beacon
///              state root — same code already cross-checked against
///              synthetic data in `SSZ.t.sol`, now exercised on genuine
///              mainnet data.
///
///         What this does NOT verify on-chain (still open, see PLAN.md):
///         the aggregate BLS signature's validity. `updateState()` on
///         `LightClientVerifierBLSGeneral` hashes-to-curve with a
///         simplified, non-RFC9380 scheme (see that contract's
///         `_hashToG2` doc comment) — NOT bit-compatible with Ethereum's
///         real signing scheme, so running the real signature through it
///         would prove nothing (or worse, look like it proves something).
///         The real signature IS verified, correctly, entirely OFF-CHAIN by
///         `bls-validators/verify_real_snapshot.ts` (full RFC9380
///         `expand_message_xmd`+hash_to_field via noble/curves, real
///         `signing_root`) — porting that hash-to-curve on-chain is a
///         separate, substantial remaining step (full RFC9380 XMD expansion
///         in Solidity), deliberately not attempted here.
contract LightClientVerifierBLSRealTest is Test {
    LightClientVerifierBLSGeneral lightClient;
    uint256 constant BATCH_SIZE = 64;
    uint256 constant CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA = 86;

    function setUp() public {
        lightClient = new LightClientVerifierBLSGeneral();
    }

    function _dumpSnapshot() internal returns (string memory json) {
        string[] memory cmd = new string[](2);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/dump_snapshot.ts";
        bytes memory result = vm.ffi(cmd);
        json = string(result);
    }

    function test_registersRealMainnetCommittee() public {
        string memory json = _dumpSnapshot();
        bytes[] memory pubkeys = vm.parseJsonBytesArray(json, ".pubkeysEip2537");
        assertEq(pubkeys.length, 512, "expected the real 512-validator sync committee");

        uint256 totalGas = 0;
        for (uint256 offset = 0; offset < pubkeys.length; offset += BATCH_SIZE) {
            uint256 end = offset + BATCH_SIZE > pubkeys.length ? pubkeys.length : offset + BATCH_SIZE;
            bytes[] memory batch = new bytes[](end - offset);
            for (uint256 i = offset; i < end; i++) {
                batch[i - offset] = pubkeys[i];
            }
            uint256 gasBefore = gasleft();
            lightClient.addValidators(batch);
            totalGas += gasBefore - gasleft();
        }
        console2.log("addValidators TOTAL gas, REAL mainnet committee (512, 8 batches):", totalGas);

        lightClient.finalize();
        assertEq(lightClient.numValidators(), 512);
        assertEq(lightClient.threshold(), 342, "ceil(2*512/3) must match Ethereum's real sync committee quorum");
    }

    /// @notice The real SSZ merkle proof (Milestone 5 step 2, now run
    ///         on-chain via SSZ.sol instead of just off-chain) — proves the
    ///         real 512-key committee genuinely is the one Ethereum's
    ///         actual beacon state commits to, using ONLY real captured
    ///         data, no synthetic test fixtures.
    function test_realCommitteeMerkleProof_verifiesOnChain() public {
        string memory json = _dumpSnapshot();
        bytes[] memory pubkeysCompressed = vm.parseJsonBytesArray(json, ".pubkeysCompressed");
        bytes memory aggregatePubkey = vm.parseJsonBytes(json, ".aggregatePubkeyCompressed");
        bytes32 stateRoot = bytes32(vm.parseJsonBytes(json, ".bootstrapHeaderStateRoot"));
        bytes32[] memory branch = vm.parseJsonBytes32Array(json, ".currentSyncCommitteeBranch");

        uint256 gasBefore = gasleft();
        bytes32 committeeRoot = SSZ.hashTreeRootSyncCommittee(pubkeysCompressed, aggregatePubkey);
        bool valid = SSZ.isValidMerkleBranch(
            committeeRoot, branch, branch.length, CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA, stateRoot
        );
        console2.log("real committee root + merkle verify gas:", gasBefore - gasleft());

        assertTrue(valid, "real mainnet sync committee must verify against the real captured beacon state root");
    }
}
