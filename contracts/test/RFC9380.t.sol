// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {RFC9380} from "../src/RFC9380.sol";

/// @notice Milestone 5 (see PLAN.md) — proves RFC9380.sol's on-chain
///         hash_to_curve (BLS12-381 G2, Ethereum's real
///         `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` ciphersuite)
///         produces the EXACT SAME point as noble/curves' off-chain
///         implementation (already proven correct against live Ethereum
///         mainnet signatures — see bls-validators/sync_committee_probe.ts,
///         Milestone 5 step 1) for the same message. This is what makes
///         verifying a REAL Ethereum BLS signature on-chain possible at
///         all — see RFC9380.sol's header comment.
contract RFC9380Test is Test {
    bytes constant POP_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

    function _offChainMessagePoint(bytes32 message) internal returns (bytes memory) {
        string[] memory cmd = new string[](3);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/dump_message_point.ts";
        cmd[2] = vm.toString(message);
        // dump_message_point.ts prints a bare "0x..." hex string — Forge's
        // vm.ffi auto-decodes hex-looking stdout into raw bytes already
        // (same behavior relied on in SSZ.t.sol's _offChainCommitteeRoot).
        return vm.ffi(cmd);
    }

    function test_hashToCurveG2_matchesOffChain_arbitraryMessage() public {
        bytes32 message = keccak256("some arbitrary 32-byte message, doesn't need to be a real signing_root");

        uint256 gasBefore = gasleft();
        bytes memory onChain = RFC9380.hashToCurveG2(abi.encodePacked(message), POP_DST);
        console2.log("hashToCurveG2 gas:", gasBefore - gasleft());

        bytes memory offChain = _offChainMessagePoint(message);
        assertEq(onChain, offChain, "on-chain RFC9380.sol must match noble/curves off-chain for the same message + DST");
    }

    /// @notice Same check against the REAL signing_root from the frozen
    ///         mainnet snapshot (bls-validators/real_sync_committee_snapshot.json)
    ///         — not just an arbitrary message, the actual value a real
    ///         Ethereum sync committee signature is computed over.
    function test_hashToCurveG2_matchesOffChain_realSigningRoot() public {
        string[] memory cmd = new string[](2);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/dump_signing_root.ts";
        bytes32 signingRoot = bytes32(vm.ffi(cmd));

        bytes memory onChain = RFC9380.hashToCurveG2(abi.encodePacked(signingRoot), POP_DST);
        bytes memory offChain = _offChainMessagePoint(signingRoot);
        assertEq(onChain, offChain, "on-chain RFC9380.sol must match noble/curves for the REAL mainnet signing_root");
    }
}
