pragma circom 2.1.0;

include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";

/// ConsensusProof
///
/// Proves: "at least `k` of `n` known validators EdDSA-signed a Poseidon
/// commitment to (chainId, blockNumber, stateRoot)".
///
/// This is Milestone 3's toy light-client circuit (see docs/threat-model.md
/// #6: `n` is small and the validator keys are demo keys, NOT a real
/// consensus committee — do not use this to secure real value). It
/// deliberately does NOT verify a real block header / Merkle-Patricia-trie
/// inclusion proof (that's real-Ethereum-light-client complexity out of
/// scope for this demo, see PLAN.md Milestone 4's "replace with real
/// consensus" TODO) — `stateRoot` here is whatever value the relayer wants
/// attested, e.g. a channel's final-state hash from PaymentChannel.sol on
/// the source chain.
///
/// Public signals (in declaration order — no circuit `output`s, so no
/// prepended output signals; see channel_state.circom's comment on
/// declaration order for why that's called out explicitly):
///   chainId            - the chain this attestation is about
///   blockNumber        - monotonically increasing, so LightClientVerifier
///                        can reject stale/replayed attestations
///   stateRoot           - the attested value itself
///   validatorPubKeyX/Y[n] - the committee's public keys, checked by
///                        LightClientVerifier against ITS hardcoded/registered
///                        committee (this circuit only proves a valid quorum
///                        signed for WHATEVER keys are passed in as public
///                        input — it's the verifier contract's job to pin
///                        those keys to a specific trusted committee)
///
/// Private witness:
///   participating[n]   - 1 if validator i actually signed, 0 otherwise
///   sigS/R8x/R8y[n]     - validator i's signature (ignored/zero if not
///                        participating — EdDSAPoseidonVerifier's `enabled`
///                        flag skips the constraint entirely when 0)
template ConsensusProof(n, k) {
    signal input chainId;
    signal input blockNumber;
    signal input stateRoot;
    signal input validatorPubKeyX[n];
    signal input validatorPubKeyY[n];

    signal input participating[n];
    signal input sigS[n];
    signal input sigR8x[n];
    signal input sigR8y[n];

    component msgHash = Poseidon(3);
    msgHash.inputs[0] <== chainId;
    msgHash.inputs[1] <== blockNumber;
    msgHash.inputs[2] <== stateRoot;

    component verify[n];
    signal partialSum[n + 1];
    partialSum[0] <== 0;

    for (var i = 0; i < n; i++) {
        // participating[i] must be boolean (0 or 1) — otherwise a malicious
        // prover could inflate the quorum count with a non-boolean value.
        participating[i] * (1 - participating[i]) === 0;

        verify[i] = EdDSAPoseidonVerifier();
        verify[i].enabled <== participating[i];
        verify[i].Ax <== validatorPubKeyX[i];
        verify[i].Ay <== validatorPubKeyY[i];
        verify[i].S <== sigS[i];
        verify[i].R8x <== sigR8x[i];
        verify[i].R8y <== sigR8y[i];
        verify[i].M <== msgHash.out;

        partialSum[i + 1] <== partialSum[i] + participating[i];
    }

    // at least k of n validators must have actually signed
    component quorum = GreaterEqThan(8); // n is tiny in this demo, 8 bits is plenty
    quorum.in[0] <== partialSum[n];
    quorum.in[1] <== k;
    quorum.out === 1;
}

// n=5 demo validators, k=3 threshold (>50%) — see docs/threat-model.md #6.
component main {public [chainId, blockNumber, stateRoot, validatorPubKeyX, validatorPubKeyY]} = ConsensusProof(5, 3);
