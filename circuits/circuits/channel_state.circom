pragma circom 2.1.0;

include "circomlib/circuits/eddsaposeidon.circom";
include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";

/// ChannelStateTransition
///
/// Proves: "there exists a chain of `steps` off-chain payment-channel updates,
/// each signed by BOTH parties, with strictly increasing nonces and constant
/// total balance, starting from the channel's on-chain deposits and ending at
/// the claimed final state."
///
/// This lets a payment channel settle on-chain with a single constant-size
/// proof instead of replaying/verifying every off-chain signature — the core
/// value of Milestone 2 (see PLAN.md).
///
/// Off-chain identity note: signatures here are EdDSA (Baby Jubjub, Poseidon
/// hash) — NOT the ECDSA/secp256k1 keys used to sign Ethereum transactions.
/// Each party registers an EdDSA public key when the channel opens; that
/// registration (on-chain, ECDSA-authenticated) is what binds the two
/// identities together. See PLAN.md section 5 for the risk this implies.
///
/// Public signals (in declaration order, see `component main`):
///   channelId       - binds this proof to one specific on-chain channel
///   pubKeyAx/Ay     - partyA's registered EdDSA public key
///   pubKeyBx/By     - partyB's registered EdDSA public key
///   initBalanceA/B  - starting balances (must equal the channel's deposits)
///   contractAddress - the PaymentChannel deployment this proof is bound to
///   chainId         - the chain that deployment lives on
///   outNonce        - nonce of the final state reached by the chain
///   outBalanceA/B   - balances of the final state reached by the chain
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
///   nonce[steps], balanceA[steps], balanceB[steps]      - each update's state
///   sigA_{S,R8x,R8y}[steps], sigB_{S,R8x,R8y}[steps]    - both signatures
template ChannelStateTransition(steps) {
    // ---- public ----
    signal input channelId;
    signal input pubKeyAx;
    signal input pubKeyAy;
    signal input pubKeyBx;
    signal input pubKeyBy;
    signal input initBalanceA;
    signal input initBalanceB;
    signal input contractAddress; // uint160 range, fits comfortably in the field
    signal input chainId;

    signal output outNonce;
    signal output outBalanceA;
    signal output outBalanceB;

    // ---- private witness: the off-chain update history ----
    signal input nonce[steps];
    signal input balanceA[steps];
    signal input balanceB[steps];

    signal input sigA_S[steps];
    signal input sigA_R8x[steps];
    signal input sigA_R8y[steps];

    signal input sigB_S[steps];
    signal input sigB_R8x[steps];
    signal input sigB_R8y[steps];

    // total value locked in the channel; must be conserved across every step
    signal totalDeposit;
    totalDeposit <== initBalanceA + initBalanceB;

    // RANGE_BITS bounds each balance AND nonce to prevent field-overflow
    // tricks (e.g. balanceA = p - 1 wrapping conservation checks, or nonce
    // wrapping LessThan's soundness — see nonceRangeCheck below). 64 bits is
    // far beyond any realistic wei/token amount or update counter used in
    // this demo.
    var RANGE_BITS = 64;

    component balanceARangeCheck[steps];
    component balanceBRangeCheck[steps];
    component nonceRangeCheck[steps];
    component nonceIncreasing[steps];
    component msgHash[steps];
    component verifyA[steps];
    component verifyB[steps];

    signal prevNonce[steps + 1];
    prevNonce[0] <== 0;

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
    outBalanceA <== balanceA[steps - 1];
    outBalanceB <== balanceB[steps - 1];
}

// Fixed to 4 off-chain updates per proof for this demo. A channel with more
// history than that submits several proofs chained by (initBalance == prior
// outBalance) — not implemented here, see PLAN.md Milestone 2 TODOs.
component main {public [channelId, pubKeyAx, pubKeyAy, pubKeyBx, pubKeyBy, initBalanceA, initBalanceB, contractAddress, chainId]} = ChannelStateTransition(4);
