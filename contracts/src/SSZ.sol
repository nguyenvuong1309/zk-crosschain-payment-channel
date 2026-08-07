// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SSZ
/// @notice Milestone 5 step 5 (see PLAN.md): on-chain half of the SSZ
///         `hash_tree_root`/merkle-branch verification already proven
///         correct off-chain by `bls-validators/sync_committee_probe.ts`
///         (Milestone 5 step 2) — same algorithm, ported to Solidity, so it
///         can be measured for REAL gas cost instead of estimated. Not yet
///         wired into `LightClientVerifierBLSGeneral.sol`'s `updateState`
///         (a further integration step) — this exists to answer "is
///         verifying committee-inclusion on-chain affordable, or does it
///         need a circuit to compress" with real numbers, not a guess.
///
///         https://github.com/ethereum/consensus-specs/blob/master/ssz/simple-serialize.md
library SSZ {
    /// @notice hash_tree_root of a single BLSPubkey (Bytes48 = Vector[uint8,
    ///         48], a COMPOSITE SSZ type): pack the 48 raw bytes into 2
    ///         32-byte chunks (chunk1 zero-padded) and merkleize.
    function hashTreeRootBytes48(bytes memory pubkey48) internal pure returns (bytes32) {
        require(pubkey48.length == 48, "SSZ: pubkey must be 48 bytes");
        bytes32 chunk0;
        bytes32 chunk1raw;
        assembly {
            chunk0 := mload(add(pubkey48, 32)) // pubkey bytes [0:32)
            // mload here reads pubkey bytes [32:48) as the TOP (most
            // significant) 16 bytes of the word, with the bottom 16 bytes
            // being whatever memory happens to follow — NOT necessarily
            // zero, so it's masked below rather than trusted.
            chunk1raw := mload(add(pubkey48, 64))
        }
        // Keep only the top 16 bytes (the real pubkey[32:48) data), zero the
        // bottom 16 — this is chunk1's correct SSZ zero-padding regardless
        // of what was in memory past the declared 48-byte length.
        bytes32 chunk1 = chunk1raw & bytes32(uint256(type(uint128).max) << 128);
        return sha256(abi.encodePacked(chunk0, chunk1));
    }

    /// @notice hash_tree_root of `Vector[BLSPubkey, N]` — BLSPubkey is
    ///         composite, so elements are NOT packed together; each gets
    ///         its own leaf (via hashTreeRootBytes48), then the N leaves
    ///         (padded to the next power of 2, zero-hash padding) are
    ///         merkleized pairwise.
    function hashTreeRootPubkeysVector(bytes[] memory pubkeys) internal pure returns (bytes32) {
        uint256 n = pubkeys.length;
        uint256 size = 1;
        while (size < n) size *= 2;

        bytes32[] memory layer = new bytes32[](size);
        for (uint256 i = 0; i < n; i++) {
            layer[i] = hashTreeRootBytes48(pubkeys[i]);
        }
        // Remaining slots (if n isn't a power of 2) stay bytes32(0), which
        // IS the correct SSZ zero-hash padding for an empty basic-leaf slot.

        while (size > 1) {
            size /= 2;
            for (uint256 i = 0; i < size; i++) {
                layer[i] = sha256(abi.encodePacked(layer[2 * i], layer[2 * i + 1]));
            }
        }
        return layer[0];
    }

    /// @notice hash_tree_root of `SyncCommittee { pubkeys: Vector[BLSPubkey,
    ///         N], aggregate_pubkey: BLSPubkey }`.
    function hashTreeRootSyncCommittee(bytes[] memory pubkeys, bytes memory aggregatePubkey)
        internal
        pure
        returns (bytes32)
    {
        return sha256(abi.encodePacked(hashTreeRootPubkeysVector(pubkeys), hashTreeRootBytes48(aggregatePubkey)));
    }

    /// @notice https://github.com/ethereum/consensus-specs/blob/master/ssz/merkle-proofs.md#merkle-multiproofs
    /// @param depth Number of branch nodes / tree levels from leaf to root.
    /// @param generalizedIndex The leaf's generalized index in the full
    ///        tree (e.g. `CURRENT_SYNC_COMMITTEE_GINDEX_ELECTRA = 86`).
    function isValidMerkleBranch(
        bytes32 leaf,
        bytes32[] memory branch,
        uint256 depth,
        uint256 generalizedIndex,
        bytes32 root
    ) internal pure returns (bool) {
        require(branch.length == depth, "SSZ: branch length != depth");
        bytes32 value = leaf;
        for (uint256 i = 0; i < depth; i++) {
            bool isRightChild = (generalizedIndex >> i) & 1 == 1;
            value =
                isRightChild ? sha256(abi.encodePacked(branch[i], value)) : sha256(abi.encodePacked(value, branch[i]));
        }
        return value == root;
    }
}
