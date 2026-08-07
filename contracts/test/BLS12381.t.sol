// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {BLS12381} from "../src/BLS12381.sol";

contract BLS12381Test is Test {
    function test_mapFp2ToG2_matchesKnownOutput() public {
        // Same input/output cross-checked against @noble/curves off-chain
        // (see bls-validators/README.md) — c0=123, c1=456.
        bytes memory input = abi.encodePacked(BLS12381.encodeFp(123), BLS12381.encodeFp(456));
        bytes memory result = BLS12381.mapFp2ToG2(input);
        assertEq(result.length, 256);

        bytes memory expected =
            hex"0000000000000000000000000000000014a326bed979186647d081bd57fff09cb5950bf4e19391a5c6f7fefcfb713b803d8046075392608d364fb7a8de40e2a200000000000000000000000000000000012c040953428c98b8fc5b0ec445d2070837374366f215b16df0622baf0e2a0e644d4eb32a0b826048df3a93875ac6830000000000000000000000000000000015d76744209a59b51af2271b6391d8789b179fa6c4c3e6e374b139e6004b266eba156245b593bd20426c4c98ed3cf9af000000000000000000000000000000000c18b0e88a89cfded45c31a08fbbfb67ff772eb77e247eba748c6e12da083ca610f158f06c15cb024dd332e1a75575ff";
        assertEq(result, expected);
    }
}
