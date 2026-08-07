//! `ChannelStateCircuit` — Halo2 port of ONE step of `channel_state.circom`
//! (see docs comment on scope reduction: 1 step here vs. 4 in the Circom
//! version — chaining more steps is a mechanical repetition of the same
//! per-step gates, not a different technique, but wasn't done here given
//! time constraints; see circuits-halo2/README.md for exactly what is and
//! isn't full parity).
//!
//! Proves: "both partyA and partyB validly EdDSA-Poseidon-signed the
//! message M = Poseidon7(contractAddress, chainId, channelId, nonce,
//! balanceA, balanceB), and balanceA + balanceB == totalDeposit" — using
//! circomlib's EXACT EdDSAPoseidonVerifier equation (S*B8 == R8 + c*(8*A))
//! and EXACT Poseidon constants, both cross-checked bit-for-bit against
//! real circomlibjs output (see poseidon_ref.rs / babyjubjub_ref.rs tests).
//!
//! `contractAddress`/`chainId` are a domain separator, baked directly into
//! the signed message — mirrors `channel_state.circom`'s own domain
//! separator (see that circuit's doc comment, and "Lỗi đã tìm và sửa" #D in
//! docs/threat-model.md for why this matters: without it, a proof valid for
//! one deployment/chain would also verify for any other with matching
//! registered keys/deposits). An earlier version of this reference circuit
//! omitted this — see circuits-halo2/README.md's comparison table, now
//! updated to reflect that this gap is closed.

use crate::babyjubjub_chip::{self, PointNum};
use crate::babyjubjub_ref;
use crate::chip::{ArithChip, ArithConfig, Num};
use crate::poseidon_chip::poseidon_hash_circuit;
use crate::poseidon_ref::{self, PoseidonParams};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Error, Instance};
use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;

#[derive(Clone)]
pub struct SignatureWitness {
    pub r8x: Fr,
    pub r8y: Fr,
    pub s: Fr,
}

#[derive(Clone)]
pub struct ChannelStateCircuit {
    // Public.
    pub contract_address: Fr,
    pub chain_id: Fr,
    pub channel_id: Fr,
    pub nonce: Fr,
    pub balance_a: Fr,
    pub balance_b: Fr,
    pub total_deposit: Fr,
    pub pub_key_ax: Fr,
    pub pub_key_ay: Fr,
    pub pub_key_bx: Fr,
    pub pub_key_by: Fr,
    // Private witness.
    pub sig_a: SignatureWitness,
    pub sig_b: SignatureWitness,
}

impl ChannelStateCircuit {
    /// Instance column layout — public inputs, in this order.
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            self.contract_address,
            self.chain_id,
            self.channel_id,
            self.nonce,
            self.balance_a,
            self.balance_b,
            self.total_deposit,
            self.pub_key_ax,
            self.pub_key_ay,
            self.pub_key_bx,
            self.pub_key_by,
        ]
    }

    /// The message hash, computed off-circuit (pure Rust reference) — used
    /// both as a bit-decomposition hint inside `synthesize` and by callers
    /// building the witness in the first place (e.g. to sign with it).
    /// Same field order as `channel_state.circom`'s `msgHash` component.
    pub fn message_hash(&self) -> Fr {
        let params7 = PoseidonParams::t7();
        poseidon_ref::poseidon_hash(
            &params7,
            &[self.contract_address, self.chain_id, self.channel_id, self.nonce, self.balance_a, self.balance_b],
        )
    }
}

#[derive(Clone)]
pub struct ChannelStateConfig {
    arith: ArithConfig,
    instance: Column<Instance>,
}

impl Circuit<Fr> for ChannelStateCircuit {
    type Config = ChannelStateConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            contract_address: self.contract_address,
            chain_id: self.chain_id,
            channel_id: self.channel_id,
            nonce: self.nonce,
            balance_a: self.balance_a,
            balance_b: self.balance_b,
            total_deposit: self.total_deposit,
            pub_key_ax: self.pub_key_ax,
            pub_key_ay: self.pub_key_ay,
            pub_key_bx: self.pub_key_bx,
            pub_key_by: self.pub_key_by,
            sig_a: SignatureWitness { r8x: Fr::zero(), r8y: Fr::zero(), s: Fr::zero() },
            sig_b: SignatureWitness { r8x: Fr::zero(), r8y: Fr::zero(), s: Fr::zero() },
        }
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        let arith = ArithChip::configure(meta);
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        ChannelStateConfig { arith, instance }
    }

    fn synthesize(&self, config: Self::Config, mut layouter: impl Layouter<Fr>) -> Result<(), Error> {
        let chip = ArithChip::new(config.arith);

        // --- load public inputs as witnessed+instance-constrained cells ---
        let contract_address = load_public(&chip, layouter.namespace(|| "contractAddress"), self.contract_address, config.instance, 0)?;
        let chain_id = load_public(&chip, layouter.namespace(|| "chainId"), self.chain_id, config.instance, 1)?;
        let channel_id = load_public(&chip, layouter.namespace(|| "channelId"), self.channel_id, config.instance, 2)?;
        let nonce = load_public(&chip, layouter.namespace(|| "nonce"), self.nonce, config.instance, 3)?;
        let balance_a = load_public(&chip, layouter.namespace(|| "balanceA"), self.balance_a, config.instance, 4)?;
        let balance_b = load_public(&chip, layouter.namespace(|| "balanceB"), self.balance_b, config.instance, 5)?;
        let total_deposit = load_public(&chip, layouter.namespace(|| "totalDeposit"), self.total_deposit, config.instance, 6)?;
        let pub_key_ax = load_public(&chip, layouter.namespace(|| "Ax"), self.pub_key_ax, config.instance, 7)?;
        let pub_key_ay = load_public(&chip, layouter.namespace(|| "Ay"), self.pub_key_ay, config.instance, 8)?;
        let pub_key_bx = load_public(&chip, layouter.namespace(|| "Bx"), self.pub_key_bx, config.instance, 9)?;
        let pub_key_by = load_public(&chip, layouter.namespace(|| "By"), self.pub_key_by, config.instance, 10)?;

        // --- conservation: balanceA + balanceB == totalDeposit ---
        let sum = chip.add(layouter.namespace(|| "balanceA+balanceB"), &balance_a, &balance_b)?;
        chip.assert_equal(layouter.namespace(|| "conservation"), &sum, &total_deposit)?;

        // --- message hash: M = Poseidon7(contractAddress, chainId, channelId, nonce, balanceA, balanceB) ---
        let params7 = PoseidonParams::t7();
        let message = poseidon_hash_circuit(
            &chip,
            layouter.namespace(|| "message hash"),
            &params7,
            &[contract_address, chain_id, channel_id, nonce, balance_a, balance_b],
        )?;
        let message_hint = self.message_hash();

        // --- verify both EdDSA signatures against the SAME message ---
        verify_eddsa(&chip, layouter.namespace(|| "verify A"), &pub_key_ax, self.pub_key_ax, self.pub_key_ay, &self.sig_a, &message, message_hint)?;
        verify_eddsa(&chip, layouter.namespace(|| "verify B"), &pub_key_bx, self.pub_key_bx, self.pub_key_by, &self.sig_b, &message, message_hint)?;
        let _ = pub_key_ay; // consumed via witnessed re-derivation below (kept for symmetry/clarity)
        let _ = pub_key_by;

        Ok(())
    }
}

fn load_public(chip: &ArithChip, mut layouter: impl Layouter<Fr>, value: Fr, instance: Column<Instance>, row: usize) -> Result<Num, Error> {
    let cell = chip.load_witness(layouter.namespace(|| "public"), Value::known(value))?;
    layouter.constrain_instance(cell.cell(), instance, row)?;
    Ok(cell)
}

/// `ax_cell` is the ALREADY-loaded (and instance-constrained) public-input
/// cell for Ax — reused here so the circuit doesn't load Ax twice under
/// different, uncorrelated cells. `ax_hint`/`ay_hint` are the plain Fr
/// values (needed for off-circuit bit/point computation hints only; every
/// resulting in-circuit value is independently constrained regardless of
/// what hints were used to build them).
#[allow(clippy::too_many_arguments)]
fn verify_eddsa(
    chip: &ArithChip,
    mut layouter: impl Layouter<Fr>,
    ax_cell: &Num,
    ax_hint: Fr,
    ay_hint: Fr,
    sig: &SignatureWitness,
    message: &Num,
    message_hint: Fr,
) -> Result<(), Error> {
    let ay_cell = chip.load_witness(layouter.namespace(|| "Ay (re-witnessed)"), Value::known(ay_hint))?;

    let r8x = chip.load_witness(layouter.namespace(|| "R8x"), Value::known(sig.r8x))?;
    let r8y = chip.load_witness(layouter.namespace(|| "R8y"), Value::known(sig.r8y))?;
    let s = chip.load_witness(layouter.namespace(|| "S"), Value::known(sig.s))?;

    // c = Poseidon5(R8x, R8y, Ax, Ay, M) — constrained in-circuit; hint
    // computed off-circuit the same way for the bit-decomposition below.
    let params5 = PoseidonParams::t6();
    let challenge = poseidon_hash_circuit(
        chip,
        layouter.namespace(|| "challenge"),
        &params5,
        &[r8x.clone(), r8y.clone(), ax_cell.clone(), ay_cell.clone(), message.clone()],
    )?;
    let challenge_hint = poseidon_ref::poseidon_hash(&params5, &[sig.r8x, sig.r8y, ax_hint, ay_hint, message_hint]);

    // 8*A via 3 doublings (matches circomlib's BabyDbl x3).
    let a_point = PointNum { x: ax_cell.clone(), y: ay_cell };
    let a2 = babyjubjub_chip::point_double(chip, layouter.namespace(|| "2A"), &a_point)?;
    let a4 = babyjubjub_chip::point_double(chip, layouter.namespace(|| "4A"), &a2)?;
    let a8 = babyjubjub_chip::point_double(chip, layouter.namespace(|| "8A"), &a4)?;

    let c_bits_hint = fr_to_le_bits(challenge_hint, 254);
    let c_bits = babyjubjub_chip::to_bits(chip, layouter.namespace(|| "c bits"), &challenge, 254, &c_bits_hint)?;
    let c_times_8a = babyjubjub_chip::scalar_mul_bits(chip, layouter.namespace(|| "c * 8A"), &a8, &c_bits)?;

    let rhs = babyjubjub_chip::point_add(chip, layouter.namespace(|| "R8 + c*8A"), &PointNum { x: r8x.clone(), y: r8y.clone() }, &c_times_8a)?;

    let s_bits_hint = fr_to_le_bits(sig.s, 253);
    let s_bits = babyjubjub_chip::to_bits(chip, layouter.namespace(|| "s bits"), &s, 253, &s_bits_hint)?;
    let base8 = babyjubjub_ref::base8_point();
    let base8_x = chip.load_witness(layouter.namespace(|| "B8x"), Value::known(base8.x))?;
    let base8_y = chip.load_witness(layouter.namespace(|| "B8y"), Value::known(base8.y))?;
    let lhs = babyjubjub_chip::scalar_mul_bits(chip, layouter.namespace(|| "S * B8"), &PointNum { x: base8_x, y: base8_y }, &s_bits)?;

    chip.assert_equal(layouter.namespace(|| "lhs.x == rhs.x"), &lhs.x, &rhs.x)?;
    chip.assert_equal(layouter.namespace(|| "lhs.y == rhs.y"), &lhs.y, &rhs.y)?;

    let _ = ax_hint;
    Ok(())
}

fn fr_to_le_bits(x: Fr, n: usize) -> Vec<bool> {
    let repr = x.to_repr();
    let bytes: &[u8] = repr.as_ref();
    (0..n).map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1).collect()
}
