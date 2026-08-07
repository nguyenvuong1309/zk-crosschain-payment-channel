// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BLS12381} from "./BLS12381.sol";

/// @title RFC9380
/// @notice Milestone 5 (see PLAN.md) — the piece that was previously
///         missing to verify a REAL Ethereum BLS aggregate signature
///         on-chain: RFC9380 `hash_to_curve` for BLS12-381 G2, with
///         Ethereum's exact ciphersuite
///         (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`). EIP-2537's
///         `MAP_FP2_TO_G2` precompile already does the hard part (Simplified
///         SWU curve map + isogeny + cofactor clearing, all in one call) —
///         what was missing is everything BEFORE that: `expand_message_xmd`
///         (repeated SHA-256, RFC9380 §5.4.1) and `hash_to_field` (reducing
///         512-bit pseudorandom strings into BLS12-381's 381-bit base
///         field). Both implemented here.
///
///         Previously this repo's on-chain BLS contracts
///         (`LightClientVerifierBLS(General).sol`) used a simplified,
///         non-RFC9380 message-to-curve (`_hashToG2`, see those contracts'
///         doc comments) — this library is what makes verifying a REAL
///         Ethereum-signed message on-chain possible at all.
library RFC9380 {
    uint256 private constant B_IN_BYTES = 32; // SHA-256 output size
    uint256 private constant S_IN_BYTES = 64; // SHA-256 block size
    uint256 private constant L = 64; // bytes per reduced field element (ceil((381+128)/8), BLS12-381's security margin)

    address private constant MODEXP = address(uint160(0x05));

    // BLS12-381 base field prime (48 bytes, big-endian) — the modulus every
    // hash_to_field output gets reduced into.
    bytes private constant BASE_FIELD_MODULUS =
        hex"1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    error ModExpFailed();
    error DstTooLong();
    error LenInBytesTooLarge();

    /// @notice RFC9380 §5.4.1 `expand_message_xmd`, SHA-256 variant.
    function expandMessageXmd(bytes memory message, bytes memory dst, uint256 lenInBytes)
        internal
        pure
        returns (bytes memory)
    {
        if (dst.length > 255) revert DstTooLong();
        uint256 ell = (lenInBytes + B_IN_BYTES - 1) / B_IN_BYTES;
        if (ell > 255) revert LenInBytesTooLarge();

        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));
        bytes memory zPad = new bytes(S_IN_BYTES);
        bytes memory msgPrime = abi.encodePacked(zPad, message, uint16(lenInBytes), uint8(0), dstPrime);

        bytes32 b0 = sha256(msgPrime);
        bytes32 bPrev = sha256(abi.encodePacked(b0, uint8(1), dstPrime));

        bytes memory out = new bytes(lenInBytes);
        _writeChunk(out, 0, bPrev, lenInBytes);

        for (uint256 i = 2; i <= ell; i++) {
            bytes32 bCur = sha256(abi.encodePacked(b0 ^ bPrev, uint8(i), dstPrime));
            _writeChunk(out, (i - 1) * B_IN_BYTES, bCur, lenInBytes);
            bPrev = bCur;
        }
        return out;
    }

    /// @notice RFC9380 §5.2/§5.3 `hash_to_field` with count=2, m=2
    ///         (BLS12-381's Fp2 extension degree) — produces the two Fp2
    ///         field elements (u0, u1) `map_to_curve` needs, each EIP-2537
    ///         encoded (128 bytes: c0 || c1, 64 bytes each).
    function hashToFieldFp2(bytes memory message, bytes memory dst)
        internal
        view
        returns (bytes memory u0, bytes memory u1)
    {
        bytes memory uniformBytes = expandMessageXmd(message, dst, 4 * L); // count(2) * m(2) * L(64)

        bytes memory u0c0 = _toFpEncoded(_reduceModP(_slice(uniformBytes, 0 * L, L)));
        bytes memory u0c1 = _toFpEncoded(_reduceModP(_slice(uniformBytes, 1 * L, L)));
        bytes memory u1c0 = _toFpEncoded(_reduceModP(_slice(uniformBytes, 2 * L, L)));
        bytes memory u1c1 = _toFpEncoded(_reduceModP(_slice(uniformBytes, 3 * L, L)));

        u0 = abi.encodePacked(u0c0, u0c1);
        u1 = abi.encodePacked(u1c0, u1c1);
    }

    /// @notice Full RFC9380 `hash_to_curve` for BLS12-381 G2: hash_to_field
    ///         (above) + map_to_curve (EIP-2537 precompile, includes the
    ///         isogeny map and cofactor clearing) for each of the two field
    ///         elements, then adds the two resulting curve points — this
    ///         IS the "signature message point" a real Ethereum BLS
    ///         signature is computed/verified against.
    function hashToCurveG2(bytes memory message, bytes memory dst) internal view returns (bytes memory g2Point) {
        (bytes memory u0, bytes memory u1) = hashToFieldFp2(message, dst);
        bytes memory q0 = BLS12381.mapFp2ToG2(u0);
        bytes memory q1 = BLS12381.mapFp2ToG2(u1);
        return BLS12381.g2Add(q0, q1);
    }

    /// @dev Reduces an arbitrary-length big-endian integer (here always 64
    ///      bytes) modulo the BLS12-381 base field prime — via the MODEXP
    ///      precompile computing `base^1 mod p`, which is exactly `base mod
    ///      p` for any base, including ones wider than p. Avoids needing a
    ///      general-purpose big-integer library just for this one
    ///      reduction; MODEXP has supported arbitrary operand lengths since
    ///      Byzantium (EIP-198).
    function _reduceModP(bytes memory base) private view returns (bytes memory result) {
        bytes memory input = abi.encodePacked(
            uint256(base.length), // base length
            uint256(1), // exponent length
            uint256(BASE_FIELD_MODULUS.length), // modulus length
            base,
            uint8(1), // exponent = 1
            BASE_FIELD_MODULUS
        );
        (bool ok, bytes memory out) = MODEXP.staticcall(input);
        if (!ok) revert ModExpFailed();
        result = out;
    }

    /// @dev Left-pads a (<=48-byte) reduced field element into EIP-2537's
    ///      64-byte Fp encoding (16 zero bytes || 48-byte big-endian value).
    function _toFpEncoded(bytes memory value) private pure returns (bytes memory out) {
        out = new bytes(64);
        uint256 offset = 64 - value.length;
        for (uint256 i = 0; i < value.length; i++) {
            out[offset + i] = value[i];
        }
    }

    function _slice(bytes memory data, uint256 start, uint256 len) private pure returns (bytes memory out) {
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            out[i] = data[start + i];
        }
    }

    function _writeChunk(bytes memory out, uint256 offset, bytes32 chunk, uint256 lenInBytes) private pure {
        for (uint256 j = 0; j < 32 && offset + j < lenInBytes; j++) {
            out[offset + j] = chunk[j];
        }
    }
}
