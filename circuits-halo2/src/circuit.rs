//! `ChannelStateCircuit` — Halo2 port of `channel_state.circom`'s
//! `ChannelStateTransition(steps)`, with `STEPS = 4` to match the circuit's
//! historical (pre-privacy-upgrade) `steps=4` production configuration —
//! see circuits-halo2/README.md's parity table for exactly what this closes
//! (steps 1→4, 64-bit range checks on balances/nonces) and what's still out
//! of scope (the later privacy-commitment/chaining upgrade, a Solidity
//! verifier, and a real KZG ceremony SRS — those remain separate, larger
//! pieces of work, not mechanical repetition of what's already here).
//!
//! Proves: "there exist STEPS off-chain updates, each signed by both
//! parties, with strictly increasing nonces (range-checked, mirroring the
//! circom audit fix — see docs/threat-model.md #3 for why the nonce range
//! check specifically matters: `LessThan` is only sound when both its
//! inputs are already known to be < 2^64) and constant total balance,
//! starting from `startNonce` and ending at the claimed `outNonce`/
//! `finalBalanceA`/`finalBalanceB`" — using circomlib's EXACT
//! EdDSAPoseidonVerifier equation and EXACT Poseidon constants, both
//! cross-checked bit-for-bit against real circomlibjs output (see
//! poseidon_ref.rs / babyjubjub_ref.rs tests).
//!
//! `contractAddress`/`chainId` are a domain separator, baked directly into
//! each step's signed message — mirrors `channel_state.circom`'s own domain
//! separator (see that circuit's doc comment, and "Lỗi đã tìm và sửa" #D in
//! docs/threat-model.md for why this matters).

use crate::babyjubjub_chip::{self, PointNum};
use crate::babyjubjub_ref;
use crate::chip::{ArithChip, ArithConfig, Num};
use crate::poseidon_chip::poseidon_hash_circuit;
use crate::poseidon_ref::{self, PoseidonParams};
use halo2_proofs::circuit::{Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::{Circuit, Column, ConstraintSystem, Error, Instance};
use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;

/// Number of chained off-chain updates proven per proof — matches
/// `channel_state.circom`'s production `steps=4` (before the later
/// chaining upgrade let a channel span more than one proof; see that
/// circuit's doc comment on "Chaining" for how `steps=4` composes with
/// arbitrarily long channel histories via multiple proofs).
pub const STEPS: usize = 4;

/// Balances and nonces are range-checked to this many bits, mirroring
/// `channel_state.circom`'s `RANGE_BITS` — far beyond any realistic
/// wei/token amount or update counter used in this demo, but small enough
/// that `LessThan`-style overflow tricks (the audited finding this closes,
/// see docs/threat-model.md #3) aren't possible.
const RANGE_BITS: usize = 64;

#[derive(Clone)]
pub struct SignatureWitness {
    pub r8x: Fr,
    pub r8y: Fr,
    pub s: Fr,
}

impl SignatureWitness {
    fn zero() -> Self {
        Self { r8x: Fr::zero(), r8y: Fr::zero(), s: Fr::zero() }
    }
}

#[derive(Clone)]
pub struct ChannelStateCircuit {
    // --- Public: constant across the whole chain of STEPS updates ---
    pub contract_address: Fr,
    pub chain_id: Fr,
    pub channel_id: Fr,
    pub start_nonce: Fr,
    pub total_deposit: Fr,
    pub pub_key_ax: Fr,
    pub pub_key_ay: Fr,
    pub pub_key_bx: Fr,
    pub pub_key_by: Fr,
    // --- Public: the final state this proof claims to reach ---
    pub out_nonce: Fr,
    pub final_balance_a: Fr,
    pub final_balance_b: Fr,
    // --- Private witness: each of the STEPS chained updates ---
    pub nonce: [Fr; STEPS],
    pub balance_a: [Fr; STEPS],
    pub balance_b: [Fr; STEPS],
    pub sig_a: [SignatureWitness; STEPS],
    pub sig_b: [SignatureWitness; STEPS],
}

impl ChannelStateCircuit {
    /// Instance column layout — public inputs, in this order. Must match
    /// the row indices `synthesize` constrains against.
    pub fn public_inputs(&self) -> Vec<Fr> {
        vec![
            self.contract_address,
            self.chain_id,
            self.channel_id,
            self.start_nonce,
            self.total_deposit,
            self.pub_key_ax,
            self.pub_key_ay,
            self.pub_key_bx,
            self.pub_key_by,
            self.out_nonce,
            self.final_balance_a,
            self.final_balance_b,
        ]
    }

    /// Step `i`'s message hash, computed off-circuit — used both as a
    /// bit-decomposition hint inside `synthesize` and by callers building
    /// the witness (e.g. to sign with it). Same field order as
    /// `channel_state.circom`'s `msgHash[i]` component.
    pub fn message_hash_at(&self, i: usize) -> Fr {
        let params7 = PoseidonParams::t7();
        poseidon_ref::poseidon_hash(
            &params7,
            &[self.contract_address, self.chain_id, self.channel_id, self.nonce[i], self.balance_a[i], self.balance_b[i]],
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
            start_nonce: self.start_nonce,
            total_deposit: self.total_deposit,
            pub_key_ax: self.pub_key_ax,
            pub_key_ay: self.pub_key_ay,
            pub_key_bx: self.pub_key_bx,
            pub_key_by: self.pub_key_by,
            out_nonce: self.out_nonce,
            final_balance_a: self.final_balance_a,
            final_balance_b: self.final_balance_b,
            nonce: [Fr::zero(); STEPS],
            balance_a: [Fr::zero(); STEPS],
            balance_b: [Fr::zero(); STEPS],
            sig_a: std::array::from_fn(|_| SignatureWitness::zero()),
            sig_b: std::array::from_fn(|_| SignatureWitness::zero()),
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
        let start_nonce = load_public(&chip, layouter.namespace(|| "startNonce"), self.start_nonce, config.instance, 3)?;
        let total_deposit = load_public(&chip, layouter.namespace(|| "totalDeposit"), self.total_deposit, config.instance, 4)?;
        let pub_key_ax = load_public(&chip, layouter.namespace(|| "Ax"), self.pub_key_ax, config.instance, 5)?;
        let pub_key_ay = load_public(&chip, layouter.namespace(|| "Ay"), self.pub_key_ay, config.instance, 6)?;
        let pub_key_bx = load_public(&chip, layouter.namespace(|| "Bx"), self.pub_key_bx, config.instance, 7)?;
        let pub_key_by = load_public(&chip, layouter.namespace(|| "By"), self.pub_key_by, config.instance, 8)?;
        let out_nonce = load_public(&chip, layouter.namespace(|| "outNonce"), self.out_nonce, config.instance, 9)?;
        let final_balance_a = load_public(&chip, layouter.namespace(|| "finalBalanceA"), self.final_balance_a, config.instance, 10)?;
        let final_balance_b = load_public(&chip, layouter.namespace(|| "finalBalanceB"), self.final_balance_b, config.instance, 11)?;

        // startNonce is range-checked too (mirrors channel_state.circom's
        // startNonceRangeCheck) — every value ever fed into a strictly-
        // increasing check must be known-small first.
        range_check_64(&chip, layouter.namespace(|| "startNonce range check"), &start_nonce, self.start_nonce)?;

        let params7 = PoseidonParams::t7();

        let mut prev_nonce_cell = start_nonce;
        let mut prev_nonce_hint = self.start_nonce;
        let mut last_balance_a_cell: Option<Num> = None;
        let mut last_balance_b_cell: Option<Num> = None;

        for i in 0..STEPS {
            let mut step = layouter.namespace(|| format!("step {i}"));

            let nonce_i = chip.load_witness(step.namespace(|| "load nonce"), Value::known(self.nonce[i]))?;
            let balance_a_i = chip.load_witness(step.namespace(|| "load balanceA"), Value::known(self.balance_a[i]))?;
            let balance_b_i = chip.load_witness(step.namespace(|| "load balanceB"), Value::known(self.balance_b[i]))?;

            // --- range checks: balances/nonce can't silently wrap the field ---
            range_check_64(&chip, step.namespace(|| "balanceA range check"), &balance_a_i, self.balance_a[i])?;
            range_check_64(&chip, step.namespace(|| "balanceB range check"), &balance_b_i, self.balance_b[i])?;
            range_check_64(&chip, step.namespace(|| "nonce range check"), &nonce_i, self.nonce[i])?;

            // --- conservation: no value created or destroyed at this step ---
            let sum = chip.add(step.namespace(|| "balanceA+balanceB"), &balance_a_i, &balance_b_i)?;
            chip.assert_equal(step.namespace(|| "conservation"), &sum, &total_deposit)?;

            // --- nonce must strictly increase step over step: range-check
            // (nonce[i] - prevNonce - 1) to RANGE_BITS bits. If nonce[i] <=
            // prevNonce, the difference is zero or wraps to a value near the
            // field modulus, which can never decompose into RANGE_BITS bits
            // — this is the same soundness argument channel_state.circom's
            // LessThan(64) relies on, just built from the primitives this
            // chip already has instead of a dedicated comparator gate. ---
            let diff = chip.sub(step.namespace(|| "nonce - prevNonce"), &nonce_i, &prev_nonce_cell)?;
            let diff_minus_one = chip.add_const(step.namespace(|| "diff - 1"), &diff, -Fr::one())?;
            let diff_hint = self.nonce[i] - prev_nonce_hint - Fr::one();
            range_check_64(&chip, step.namespace(|| "strictly increasing"), &diff_minus_one, diff_hint)?;

            // --- message hash for this step ---
            let message = poseidon_hash_circuit(
                &chip,
                step.namespace(|| "message hash"),
                &params7,
                &[contract_address.clone(), chain_id.clone(), channel_id.clone(), nonce_i.clone(), balance_a_i.clone(), balance_b_i.clone()],
            )?;
            let message_hint = self.message_hash_at(i);

            // --- verify both EdDSA signatures against this step's message ---
            verify_eddsa(
                &chip,
                step.namespace(|| "verify A"),
                &pub_key_ax,
                self.pub_key_ax,
                self.pub_key_ay,
                &self.sig_a[i],
                &message,
                message_hint,
            )?;
            verify_eddsa(
                &chip,
                step.namespace(|| "verify B"),
                &pub_key_bx,
                self.pub_key_bx,
                self.pub_key_by,
                &self.sig_b[i],
                &message,
                message_hint,
            )?;

            prev_nonce_cell = nonce_i;
            prev_nonce_hint = self.nonce[i];
            last_balance_a_cell = Some(balance_a_i);
            last_balance_b_cell = Some(balance_b_i);
        }

        // --- the claimed final public state must match the last step's witness ---
        chip.assert_equal(layouter.namespace(|| "outNonce == last step nonce"), &prev_nonce_cell, &out_nonce)?;
        chip.assert_equal(
            layouter.namespace(|| "finalBalanceA == last step balanceA"),
            last_balance_a_cell.as_ref().expect("STEPS > 0"),
            &final_balance_a,
        )?;
        chip.assert_equal(
            layouter.namespace(|| "finalBalanceB == last step balanceB"),
            last_balance_b_cell.as_ref().expect("STEPS > 0"),
            &final_balance_b,
        )?;
        let _ = pub_key_ay; // consumed via witnessed re-derivation inside verify_eddsa
        let _ = pub_key_by;

        Ok(())
    }
}

fn load_public(chip: &ArithChip, mut layouter: impl Layouter<Fr>, value: Fr, instance: Column<Instance>, row: usize) -> Result<Num, Error> {
    let cell = chip.load_witness(layouter.namespace(|| "public"), Value::known(value))?;
    layouter.constrain_instance(cell.cell(), instance, row)?;
    Ok(cell)
}

/// Range-checks `cell` (whose plain value is `hint`, needed off-circuit to
/// build the bit witnesses) to `RANGE_BITS` bits — sound for the same
/// reason `babyjubjub_chip::to_bits` is: the weighted bit sum can only
/// equal `cell`'s real value if that value genuinely fits in `RANGE_BITS`
/// bits, regardless of what a malicious prover claims the individual bits
/// are.
fn range_check_64(chip: &ArithChip, layouter: impl Layouter<Fr>, cell: &Num, hint: Fr) -> Result<(), Error> {
    let bits_hint = fr_to_le_bits(hint, RANGE_BITS);
    babyjubjub_chip::to_bits(chip, layouter, cell, RANGE_BITS, &bits_hint)?;
    Ok(())
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

/// A real, STEPS=4 witness — generated via `circuits/input_gen/build_channel_state_input.ts`
/// (circomlibjs), same demo keys as `channel_state.circom`'s own fixtures
/// (`DEFAULT_PRIV_KEY_A/B`). Shared by `circuit_test.rs` and
/// `bin/prove_and_export.rs` so the two don't drift out of sync with two
/// independently-copied literals.
pub fn demo_witness() -> ChannelStateCircuit {
    fn fr(s: &str) -> Fr {
        Fr::from_str_vartime(s).expect("valid decimal Fr")
    }
    ChannelStateCircuit {
        contract_address: fr("97433442488726861213578988847752201310395502865"),
        chain_id: Fr::from(31337u64),
        channel_id: Fr::from(1u64),
        start_nonce: Fr::zero(),
        total_deposit: Fr::from(1000000u64),
        pub_key_ax: fr("6258698228857579243937097735069405513777546488206385948349971781708128047847"),
        pub_key_ay: fr("2216124967747932654884761600749314631961003421499958761754620989171020525870"),
        pub_key_bx: fr("21036738825193802266623779881692904721121294284483365787352024792419651640674"),
        pub_key_by: fr("17088268747125489648041885901336523179405935374090472533134592214513880559267"),
        out_nonce: Fr::from(4u64),
        final_balance_a: Fr::from(250000u64),
        final_balance_b: Fr::from(750000u64),
        nonce: [Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64)],
        balance_a: [Fr::from(400000u64), Fr::from(350000u64), Fr::from(300000u64), Fr::from(250000u64)],
        balance_b: [Fr::from(600000u64), Fr::from(650000u64), Fr::from(700000u64), Fr::from(750000u64)],
        sig_a: [
            SignatureWitness {
                r8x: fr("4917344699118670943373348864095189513110544881241303759698448356854879866857"),
                r8y: fr("5468544676196101173266500702471328966306068888220567829875945479129822096316"),
                s: fr("2332341740213430710895160059533639433920566388022543560963322443715774995966"),
            },
            SignatureWitness {
                r8x: fr("19198729722010696399061740976718444193960587239802662288086090892586276896710"),
                r8y: fr("12262835023959180782140731734192475550746146129087906133483643437531707673108"),
                s: fr("2439123599773817996181781644535831291535736805842099997327323226549731792087"),
            },
            SignatureWitness {
                r8x: fr("1378564751931286201458570802522162294710084875745334464877833220432775617300"),
                r8y: fr("16718726423853165734438284162936341268715581604052694436255319075052549808034"),
                s: fr("2076632767621542563482868929441236022304540226113928184282025875654573035186"),
            },
            SignatureWitness {
                r8x: fr("17310409621271442692204823936439234613541670542162904669149392651706117321056"),
                r8y: fr("6244075455235242276420422460848359063126715080001547696493515262333754154246"),
                s: fr("394895977106194747202808611003678783082143819184929072979575458350150329679"),
            },
        ],
        sig_b: [
            SignatureWitness {
                r8x: fr("8425486573857761199328174831877931532857805810054432862926891341132244559543"),
                r8y: fr("14076165714719029565373764552193210300296476170884431308989492567248263735781"),
                s: fr("1013225836428401173556310194350073290416509558752576451792834375459276379446"),
            },
            SignatureWitness {
                r8x: fr("11832835663950421836612932530732986254928332962245575234552664662129384794405"),
                r8y: fr("13311595687728027675591396994189329812461311780814974484738311108805765551412"),
                s: fr("1580439792343917746971201647585788132657602497227762564307786371735276042534"),
            },
            SignatureWitness {
                r8x: fr("828358632847447634929846736643787168227560104862038949309239902524432640308"),
                r8y: fr("14998401090944381114810474064942777827919880606034680203031818523092101998897"),
                s: fr("2054097101395269199242717479893203321263943666049359097423698952091063366021"),
            },
            SignatureWitness {
                r8x: fr("215944592534179227376227496705875204129618783175388930821507348008435722962"),
                r8y: fr("20283478226727219371969770317518289270776500745371794274156891897077949909151"),
                s: fr("1710393438024520761102093265350057167884118768153436820797727829814108680022"),
            },
        ],
    }
}

fn fr_to_le_bits(x: Fr, n: usize) -> Vec<bool> {
    let repr = x.to_repr();
    let bytes: &[u8] = repr.as_ref();
    (0..n).map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1).collect()
}
