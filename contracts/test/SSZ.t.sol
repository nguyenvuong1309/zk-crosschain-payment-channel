// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {SSZ} from "../src/SSZ.sol";

/// @notice Milestone 5 step 5 (see PLAN.md) — proves SSZ.sol's on-chain
///         hash_tree_root/merkle-branch implementation agrees with the
///         off-chain one already verified against REAL Ethereum mainnet
///         data (bls-validators/sync_committee_probe.ts, Milestone 5 step
///         2), and measures its REAL gas cost at 512-validator scale — the
///         number Milestone 5's "on-chain vs circuit" decision needs.
contract SSZHarness {
    function hashTreeRootSyncCommittee(bytes[] memory pubkeys, bytes memory aggregatePubkey)
        external
        pure
        returns (bytes32)
    {
        return SSZ.hashTreeRootSyncCommittee(pubkeys, aggregatePubkey);
    }

    function isValidMerkleBranch(bytes32 leaf, bytes32[] memory branch, uint256 depth, uint256 gindex, bytes32 root)
        external
        pure
        returns (bool)
    {
        return SSZ.isValidMerkleBranch(leaf, branch, depth, gindex, root);
    }
}

contract SSZTest is Test {
    SSZHarness harness;
    string constant KEYS_PATH = "../bls-validators/keys_general_512.json";

    function setUp() public {
        harness = new SSZHarness();
    }

    function _dumpPubkeysCompressed() internal returns (string memory json) {
        string[] memory cmd = new string[](4);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/dump_pubkeys.ts";
        cmd[2] = KEYS_PATH;
        cmd[3] = "compressed";
        bytes memory result = vm.ffi(cmd);
        json = string(result);
    }

    function _offChainCommitteeRoot() internal returns (bytes32) {
        string[] memory cmd = new string[](3);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/dump_committee_root.ts";
        cmd[2] = KEYS_PATH;
        bytes memory result = vm.ffi(cmd);
        // dump_committee_root.ts prints a bare "0x..." hex string on
        // stdout — Forge's vm.ffi auto-detects hex-looking output and
        // returns it ALREADY DECODED as raw bytes (not the literal ASCII
        // string), so this is just a reinterpret, no parsing needed.
        return bytes32(result);
    }

    /// @notice The main deliverable: on-chain SSZ.hashTreeRootSyncCommittee
    ///         over the REAL 512-key demo committee (same one
    ///         LightClientVerifierBLSGeneral.t.sol uses) produces the EXACT
    ///         SAME root as the off-chain TypeScript implementation already
    ///         proven correct against live Ethereum mainnet data. Also
    ///         reports the real gas cost.
    function test_hashTreeRootSyncCommittee_matchesOffChainAndMeasuresGas() public {
        string memory dumped = _dumpPubkeysCompressed();
        bytes[] memory pubkeys = vm.parseJsonBytesArray(dumped, ".pubkeys");
        bytes memory aggregatePubkey = vm.parseJsonBytes(dumped, ".aggregatePubkeyCompressed");
        assertEq(pubkeys.length, 512, "expected 512-validator demo committee");

        uint256 gasBefore = gasleft();
        bytes32 onChainRoot = harness.hashTreeRootSyncCommittee(pubkeys, aggregatePubkey);
        uint256 gasUsed = gasBefore - gasleft();
        console2.log("hashTreeRootSyncCommittee(512 pubkeys) gas:", gasUsed);

        bytes32 offChainRoot = _offChainCommitteeRoot();
        assertEq(
            onChainRoot, offChainRoot, "on-chain SSZ.sol root must match off-chain sync_committee_probe.ts algorithm"
        );
    }

    /// @notice isValidMerkleBranch correctness, independent of committee
    ///         scale — a small hand-built tree (depth 3, 8 leaves) so the
    ///         expected root/branch can be verified by inspection, not
    ///         trusted from the same code being tested.
    function test_isValidMerkleBranch_smallHandBuiltTree() public view {
        // 8 leaves -> depth 3. leaf[5] is the one we prove inclusion of
        // (generalized index = 8 + 5 = 13, i.e. 0b1101).
        bytes32[8] memory leaves;
        for (uint256 i = 0; i < 8; i++) {
            leaves[i] = keccak256(abi.encodePacked("leaf", i));
        }

        bytes32[4] memory level1;
        for (uint256 i = 0; i < 4; i++) {
            level1[i] = sha256(abi.encodePacked(leaves[2 * i], leaves[2 * i + 1]));
        }
        bytes32[2] memory level2;
        level2[0] = sha256(abi.encodePacked(level1[0], level1[1]));
        level2[1] = sha256(abi.encodePacked(level1[2], level1[3]));
        bytes32 root = sha256(abi.encodePacked(level2[0], level2[1]));

        // Proving leaf[5]: sibling at each level going up.
        bytes32[] memory branch = new bytes32[](3);
        branch[0] = leaves[4]; // sibling of leaves[5] at the leaf level
        branch[1] = level1[3]; // wait — leaves[5] pairs with leaves[4] into level1[2]; level1[2]'s sibling is level1[3]
        branch[2] = level2[0]; // level2[1]'s sibling is level2[0]

        uint256 gindex = 8 + 5; // 13
        assertTrue(harness.isValidMerkleBranch(leaves[5], branch, 3, gindex, root));

        // Tampered leaf must fail.
        assertFalse(harness.isValidMerkleBranch(keccak256("wrong"), branch, 3, gindex, root));
        // Tampered root must fail.
        assertFalse(harness.isValidMerkleBranch(leaves[5], branch, 3, gindex, keccak256("wrong-root")));
    }
}
