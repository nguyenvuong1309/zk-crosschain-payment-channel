// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console2} from "forge-std/Test.sol";
import {LightClientVerifierBLSGeneral} from "../src/LightClientVerifierBLSGeneral.sol";
import {SSZ} from "../src/SSZ.sol";
import {RFC9380} from "../src/RFC9380.sol";
import {BLS12381} from "../src/BLS12381.sol";

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
///           3. The real aggregate BLS signature ACTUALLY VERIFIES on-chain
///              — `RFC9380.sol`'s real hash_to_curve (proven bit-identical
///              to noble/curves in `RFC9380.t.sol`) computes the message
///              point from the real `signing_root`, and
///              `BLS12381.pairingCheck` confirms
///              `e(aggPubkey, M) == e(G1, signature)` for the REAL
///              participating validators' aggregate pubkey and the REAL
///              signature — full end-to-end verification of a genuine
///              Ethereum consensus signature, using only this repo's own
///              code (no external light-client library).
///
///         `LightClientVerifierBLSGeneral.updateState()` itself still uses
///         its OWN simplified, non-RFC9380 message-to-curve (see that
///         contract's `_hashToG2` doc comment) — deliberately not changed
///         here, since doing so would be a breaking change to an already
///         tested/used contract, a separate integration step from "prove
///         the real primitives work". This test verifies the real signature
///         directly via `RFC9380`/`BLS12381`, not through
///         `LightClientVerifierBLSGeneral.updateState()`.
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

    /// @notice THE full deliverable: a REAL Ethereum sync committee
    ///         aggregate BLS signature, verified on-chain from scratch —
    ///         real signing_root (SSZ, computed in dump_signing_root.ts,
    ///         same algorithm as SSZ.sol/EthereumSSZHeader logic embedded
    ///         in the dump scripts) -> real hash_to_curve (RFC9380.sol) ->
    ///         real pairing check (BLS12381.sol) against the real
    ///         participating validators' aggregate pubkey and the real
    ///         signature. No shortcuts, no simplified scheme — this is
    ///         what Milestone 5's "consensus thật" was ultimately for.
    function test_realAggregateSignature_verifiesOnChain() public {
        bytes32 signingRoot = _dumpSigningRoot();
        string memory inputs = _dumpVerificationInputs();
        bytes memory aggPubkey = vm.parseJsonBytes(inputs, ".participatingAggPubkeyEip2537");
        bytes memory signature = vm.parseJsonBytes(inputs, ".signatureEip2537");
        uint256 participantCount = vm.parseJsonUint(inputs, ".participantCount");
        console2.log("participants:", participantCount, "/ 512");

        bytes memory negG1Generator =
            hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";

        uint256 gasBefore = gasleft();
        bytes memory messagePoint =
            RFC9380.hashToCurveG2(abi.encodePacked(signingRoot), "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");
        bytes memory pairingInput = abi.encodePacked(aggPubkey, messagePoint, negG1Generator, signature);
        bool valid = BLS12381.pairingCheck(pairingInput);
        console2.log("real signature verification gas (hash-to-curve + pairing):", gasBefore - gasleft());

        assertTrue(valid, "real Ethereum mainnet sync committee aggregate signature must verify on-chain");
    }

    function _dumpSigningRoot() internal returns (bytes32) {
        string[] memory cmd = new string[](2);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/dump_signing_root.ts";
        return bytes32(vm.ffi(cmd));
    }

    function _dumpVerificationInputs() internal returns (string memory) {
        string[] memory cmd = new string[](2);
        cmd[0] = "../bls-validators/node_modules/.bin/tsx";
        cmd[1] = "../bls-validators/dump_real_verification_inputs.ts";
        return string(vm.ffi(cmd));
    }
}
