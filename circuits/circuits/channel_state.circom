pragma circom 2.1.0;

include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/// ChannelStateTransition
///
/// Proves: "there exists a chain of `steps` off-chain payment-channel updates,
/// each signed by BOTH parties, with strictly increasing nonces and constant
/// total balance, starting from SOME anchor state and ending at the claimed
/// final state." The anchor can be either the channel's genesis deposits
/// (nonce 0) or a PRIOR proof's committed final state — see "Chaining" below.
///
/// This lets a payment channel settle on-chain with a constant-size proof
/// per `steps` updates instead of replaying/verifying every off-chain
/// signature — the core value of Milestone 2 (see PLAN.md).
///
/// Off-chain identity note: signatures here are EdDSA (Baby Jubjub, Poseidon
/// hash) — NOT the ECDSA/secp256k1 keys used to sign Ethereum transactions.
/// Each party registers an EdDSA public key when the channel opens; that
/// registration (on-chain, ECDSA-authenticated) is what binds the two
/// identities together. See PLAN.md section 5 for the risk this implies.
///
/// Public signals (in declaration order, see `component main`):
///   channelId         - binds this proof to one specific on-chain channel
///   pubKeyAx/Ay       - partyA's registered EdDSA public key
///   pubKeyBx/By       - partyB's registered EdDSA public key
///   contractAddress   - the PaymentChannel deployment this proof is bound to
///   chainId           - the chain that deployment lives on
///   startNonce        - the nonce this proof's internal chain starts from
///                        (0 for a genesis-anchored proof; the on-chain
///                        channel's current `nonce` for a continuation proof
///                        — see "Chaining" below)
///   outNonce          - nonce of the final state reached by the chain
///   startCommitment   - Poseidon(startBalanceA, startBalanceB, startBlinding)
///   endCommitment     - Poseidon(outBalanceA, outBalanceB, endBlinding)
///
/// **Privacy note**: balances are NEVER public signals, at either end of the
/// chain — only Poseidon commitments to them are. Off-chain history was
/// already private (that's the whole point of this circuit); this hides the
/// settled split at proof-boundary time too, including every intermediate
/// checkpoint in a chained proof sequence (see "Chaining"), not just the
/// very first version of this circuit's final state. The contract only
/// requires a commitment opened — balances + blinding revealed and checked
/// on-chain — at `withdraw()` time, since real funds must move to real
/// amounts then; that reveal is unavoidable for on-chain settlement (see
/// PLAN.md). What this buys is hiding every number for as long as possible.
///
/// **Chaining (steps > `steps` per proof)**: a channel with more off-chain
/// updates than fit in one proof's `steps` submits SEVERAL proofs instead of
/// one, each covering the NEXT `steps` updates:
///   - The first proof anchors to genesis: `startNonce = 0`, and
///     `startCommitment` must equal `Poseidon(depositA, depositB, 0)` — a
///     fixed, publicly-computable value (deposits are already public at
///     `open()` time, and `0` is a fixed canonical blinding for this one
///     anchor case, not a secret — nothing new is hidden or leaked here).
///     Checked on-chain in `PaymentChannel._verifyChannelProof`.
///   - Every SUBSEQUENT proof anchors to the PRIOR proof's own
///     `endCommitment`/`outNonce`: `startNonce` must equal the channel's
///     currently-posted `nonce`, and `startCommitment` must equal the
///     channel's currently-posted `balanceCommitment` — both already stored
///     on-chain by the prior proof's `closeWithProof`/`challengeWithProof`
///     call, so the contract can check equality directly without ever
///     learning the actual balances. This is why `startCommitment` and
///     `endCommitment` use the EXACT SAME formula (`Poseidon(balanceA,
///     balanceB, blinding)`, 3 inputs, no nonce) — a later proof's start
///     must be checkable against an earlier proof's end with a plain
///     equality, not a re-derivation.
///   Each proof only costs `steps` worth of constraints regardless of how
///   many proofs a channel's full history eventually takes — the whole
///   point of chaining instead of just raising `steps` (which still hits a
///   hard wall eventually, only a higher one, and makes EVERY proof pay for
///   the worst case).
///
/// `contractAddress`/`chainId` are a domain separator, mirroring
/// PaymentChannel.sol's `hashState()` (see its doc comment for why): without
/// them, a proof valid for channelId N on one deployment of this contract
/// would also be valid for channelId N on ANY other deployment with matching
/// registered EdDSA keys/deposits — e.g. this project's own Chain A / Chain B
/// instances. Included directly in the signed message (not just carried as
/// an unchecked public signal) so the EdDSA signatures themselves are
/// domain-bound, not just the proof's public inputs.
///
/// Private signals (witness, supplied by whichever party generates the proof):
///   startBalanceA/B, startBlinding                      - the anchor state
///     this proof's chain starts from (channel deposits for a genesis proof;
///     whatever a prior proof's endCommitment opens to, for a continuation
///     proof — the prover must already know this to have generated that
///     prior proof, or have received it from whoever did).
///   nonce[steps], balanceA[steps], balanceB[steps]      - each update's state
///   sigA_{S,R8x,R8y}[steps], sigB_{S,R8x,R8y}[steps]    - both signatures
///   endBlinding                                         - random scalar,
///     chosen by the prover, that blinds `endCommitment` (without it, the
///     commitment would be trivially brute-forceable since balances are
///     small, bounded integers — Poseidon isn't hiding on its own for a
///     low-entropy input). The prover must remember `endBlinding` to
///     withdraw later (or to generate the NEXT chained proof) — losing it
///     means losing the ability to open/continue from this commitment (see
///     PaymentChannel.sol's `withdrawWithOpening`).
template ChannelStateTransition(steps) {
    // ---- public ----
    signal input channelId;
    signal input pubKeyAx;
    signal input pubKeyAy;
    signal input pubKeyBx;
    signal input pubKeyBy;
    signal input contractAddress; // uint160 range, fits comfortably in the field
    signal input chainId;
    signal input startNonce;

    signal output outNonce;
    signal output startCommitment;
    signal output endCommitment;

    // ---- private witness: the anchor + the off-chain update history ----
    signal input startBalanceA;
    signal input startBalanceB;
    signal input startBlinding;

    signal input nonce[steps];
    signal input balanceA[steps];
    signal input balanceB[steps];
    signal input endBlinding;

    signal input sigA_S[steps];
    signal input sigA_R8x[steps];
    signal input sigA_R8y[steps];

    signal input sigB_S[steps];
    signal input sigB_R8x[steps];
    signal input sigB_R8y[steps];

    // total value locked in the channel; must be conserved across every step
    signal totalDeposit;
    totalDeposit <== startBalanceA + startBalanceB;

    // RANGE_BITS bounds each balance AND nonce to prevent field-overflow
    // tricks (e.g. balanceA = p - 1 wrapping conservation checks, or nonce
    // wrapping LessThan's soundness — see nonceRangeCheck below). 64 bits is
    // far beyond any realistic wei/token amount or update counter used in
    // this demo.
    var RANGE_BITS = 64;

    component startBalanceARangeCheck = Num2Bits(RANGE_BITS);
    startBalanceARangeCheck.in <== startBalanceA;
    component startBalanceBRangeCheck = Num2Bits(RANGE_BITS);
    startBalanceBRangeCheck.in <== startBalanceB;
    component startNonceRangeCheck = Num2Bits(RANGE_BITS);
    startNonceRangeCheck.in <== startNonce;

    component balanceARangeCheck[steps];
    component balanceBRangeCheck[steps];
    component nonceRangeCheck[steps];
    component nonceIncreasing[steps];
    component msgHash[steps];
    component verifyA[steps];
    component verifyB[steps];

    signal prevNonce[steps + 1];
    // Chaining: starts at 0 for a genesis-anchored proof, or the prior
    // proof's outNonce for a continuation proof — see this template's doc
    // comment. Either way, PaymentChannel.sol checks `startNonce` against
    // the right on-chain value before trusting anything downstream of it.
    prevNonce[0] <== startNonce;

    for (var i = 0; i < steps; i++) {
        // --- range-check balances so they can't silently underflow/overflow
        // the field when the on-chain conservation check is later re-derived
        // from these same public/private values ---
        balanceARangeCheck[i] = Num2Bits(RANGE_BITS);
        balanceARangeCheck[i].in <== balanceA[i];

        balanceBRangeCheck[i] = Num2Bits(RANGE_BITS);
        balanceBRangeCheck[i].in <== balanceB[i];

        // --- conservation: no value created or destroyed at this step ---
        balanceA[i] + balanceB[i] === totalDeposit;

        // --- nonce must be range-checked BEFORE it's fed into LessThan:
        // LessThan(64) is only sound (see circomlib comparators.circom) when
        // BOTH its inputs are already known to be < 2^64 — otherwise a
        // prover could pick a nonce near the field's full ~254-bit range
        // that makes the field-mod subtraction inside LessThan wrap around,
        // spuriously satisfying "increasing" without a real numeric
        // increase (audit finding, Milestone 4: see docs/threat-model.md #3
        // and PLAN.md). balanceA/B already had this range check; nonce
        // didn't. ---
        nonceRangeCheck[i] = Num2Bits(RANGE_BITS);
        nonceRangeCheck[i].in <== nonce[i];

        // --- nonce must strictly increase step over step (replay/reorder
        // protection: a stale or duplicated update can never appear in a
        // valid chain) ---
        nonceIncreasing[i] = LessThan(64);
        nonceIncreasing[i].in[0] <== prevNonce[i];
        nonceIncreasing[i].in[1] <== nonce[i];
        nonceIncreasing[i].out === 1;
        prevNonce[i + 1] <== nonce[i];

        // --- message both parties actually signed off-chain: a Poseidon
        // commitment to (contractAddress, chainId, channelId, nonce,
        // balanceA, balanceB), mirroring PaymentChannel.sol's hashState()
        // (domain-separated) but with a ZK-cheap hash ---
        msgHash[i] = Poseidon(6);
        msgHash[i].inputs[0] <== contractAddress;
        msgHash[i].inputs[1] <== chainId;
        msgHash[i].inputs[2] <== channelId;
        msgHash[i].inputs[3] <== nonce[i];
        msgHash[i].inputs[4] <== balanceA[i];
        msgHash[i].inputs[5] <== balanceB[i];

        // --- both signatures must verify against the channel's registered
        // EdDSA public keys; EdDSAPoseidonVerifier is an asserting verifier
        // (the whole proof fails to satisfy its constraints if a signature
        // is invalid or forged) ---
        verifyA[i] = EdDSAPoseidonVerifier();
        verifyA[i].enabled <== 1;
        verifyA[i].Ax <== pubKeyAx;
        verifyA[i].Ay <== pubKeyAy;
        verifyA[i].S <== sigA_S[i];
        verifyA[i].R8x <== sigA_R8x[i];
        verifyA[i].R8y <== sigA_R8y[i];
        verifyA[i].M <== msgHash[i].out;

        verifyB[i] = EdDSAPoseidonVerifier();
        verifyB[i].enabled <== 1;
        verifyB[i].Ax <== pubKeyBx;
        verifyB[i].Ay <== pubKeyBy;
        verifyB[i].S <== sigB_S[i];
        verifyB[i].R8x <== sigB_R8x[i];
        verifyB[i].R8y <== sigB_R8y[i];
        verifyB[i].M <== msgHash[i].out;
    }

    outNonce <== nonce[steps - 1];

    // Same 3-input Poseidon formula at both ends of the chain on purpose —
    // see this template's doc comment on Chaining: it's what lets the
    // contract check "does proof N+1's start match proof N's end" with a
    // plain field equality, no re-derivation.
    component startCommitmentHash = Poseidon(3);
    startCommitmentHash.inputs[0] <== startBalanceA;
    startCommitmentHash.inputs[1] <== startBalanceB;
    startCommitmentHash.inputs[2] <== startBlinding;
    startCommitment <== startCommitmentHash.out;

    component endCommitmentHash = Poseidon(3);
    endCommitmentHash.inputs[0] <== balanceA[steps - 1];
    endCommitmentHash.inputs[1] <== balanceB[steps - 1];
    endCommitmentHash.inputs[2] <== endBlinding;
    endCommitment <== endCommitmentHash.out;
}

// `steps` off-chain updates per proof — a channel with more history than
// that submits several proofs, chained via startCommitment/startNonce
// matching the prior proof's endCommitment/outNonce (see this file's doc
// comment on Chaining). This is what makes the true per-proof limit
// unbounded in aggregate, unlike simply raising this constant.
component main {public [channelId, pubKeyAx, pubKeyAy, pubKeyBx, pubKeyBy, contractAddress, chainId, startNonce]} = ChannelStateTransition(4);
