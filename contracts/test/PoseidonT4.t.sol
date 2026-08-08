// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PoseidonT4Deployer, IPoseidonT4} from "../src/PoseidonT4.sol";

/// @notice Sanity-checks the raw-bytecode Poseidon(3) contract (see
///         PoseidonT4.sol) against a known-good off-chain value computed by
///         circomlibjs itself, so a bytecode-generation mistake doesn't
///         silently produce a Poseidon variant that disagrees with what
///         channel_state.circom actually proves.
contract PoseidonT4Test is Test {
    IPoseidonT4 poseidonT4;

    function setUp() public {
        PoseidonT4Deployer deployer = new PoseidonT4Deployer();
        poseidonT4 = IPoseidonT4(deployer.deploy());
    }

    /// @dev Expected value from:
    ///      `node -e "require('circomlibjs').buildPoseidon().then(p=>console.log(p.F.toObject(p([1n,2n,3n]))))"`
    function test_poseidon3_matchesCircomlibjs() public view {
        uint256[3] memory input = [uint256(1), uint256(2), uint256(3)];
        uint256 result = poseidonT4.poseidon(input);
        assertEq(result, 6542985608222806190361240322586112750744169038454362455181422643027100751666);
    }
}
