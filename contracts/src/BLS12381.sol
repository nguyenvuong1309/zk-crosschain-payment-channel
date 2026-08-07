// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title BLS12381
/// @notice Thin wrapper around the EIP-2537 BLS12-381 precompiles (live from
///         the Prague/Pectra hardfork). Used by `LightClientVerifierBLS.sol`
///         to verify REAL BLS12-381 aggregate signatures from the demo
///         validator committee (Milestone 4 — see docs/threat-model.md #6:
///         still a small simulated committee, not Ethereum's real sync
///         committee, but now using genuine BLS12-381 crypto + genuine
///         pairing checks instead of 5 independent EdDSA signatures).
///
/// Field element encoding (EIP-2537): each Fp element is 64 bytes —
/// 16 zero-padding bytes followed by the 48-byte big-endian value. A G1
/// point is 128 bytes (x, y). A G2 point is 256 bytes (x.c0, x.c1, y.c0,
/// y.c1 — Fp2 coordinates).
library BLS12381 {
    address internal constant G1ADD = address(uint160(0x0B));
    address internal constant MAP_FP2_TO_G2 = address(uint160(0x11));
    address internal constant PAIRING_CHECK = address(uint160(0x0F));

    error PrecompileCallFailed(address precompile);

    /// @notice Adds two G1 points (128 bytes each).
    function g1Add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        (bool ok, bytes memory result) = G1ADD.staticcall(abi.encodePacked(a, b));
        if (!ok) revert PrecompileCallFailed(G1ADD);
        return result;
    }

    /// @notice Maps an Fp2 element (128 bytes: c0, c1) to a G2 point (256
    ///         bytes) via the standard Simplified SWU map — the SAME
    ///         algorithm the "at" noble/curves G2.mapToCurve function
    ///         implements off-chain (cross-checked bit-for-bit against this
    ///         exact precompile, see bls-validators/README.md).
    function mapFp2ToG2(bytes memory fp2Element) internal view returns (bytes memory) {
        (bool ok, bytes memory result) = MAP_FP2_TO_G2.staticcall(fp2Element);
        if (!ok) revert PrecompileCallFailed(MAP_FP2_TO_G2);
        return result;
    }

    /// @notice Checks `e(pairs[0].g1, pairs[0].g2) * e(pairs[1].g1, pairs[1].g2) * ... == 1`
    ///         in the target group. `input` is the concatenation of
    ///         (G1 || G2) 384-byte chunks, one per pair.
    function pairingCheck(bytes memory input) internal view returns (bool) {
        (bool ok, bytes memory result) = PAIRING_CHECK.staticcall(input);
        if (!ok) revert PrecompileCallFailed(PAIRING_CHECK);
        return result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    /// @notice Encodes a uint256 (must be < BLS12-381 base field order, i.e.
    ///         fits in 48 bytes) as a 64-byte zero-padded Fp element.
    function encodeFp(uint256 value) internal pure returns (bytes memory out) {
        out = new bytes(64);
        assembly {
            mstore(add(out, 64), value)
        }
    }
}
