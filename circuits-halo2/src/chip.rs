//! A minimal "standard PLONK gate" chip: rows express either
//! `out = a * b` (both witnessed), `out = a + b` (both witnessed),
//! `out = a + k` or `out = a * k` where `k` is a genuine `Fixed` column
//! value (baked into the constraint polynomial itself, not just claimed by
//! the witness — important for constants like Poseidon round constants or
//! curve coefficients to actually be enforced, not merely asserted).
//!
//! This is the standard technique from the halo2 book's "simple example"
//! chapter, scaled up: rather than building separate bespoke chips per
//! operation, every operation in this circuit reduces to one or more calls
//! below, each emitting one row.

use halo2_proofs::circuit::{AssignedCell, Layouter, Value};
use halo2_proofs::plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector};
use halo2_proofs::poly::Rotation;
use halo2curves::bn256::Fr;

#[derive(Clone, Debug)]
pub struct ArithConfig {
    pub a: Column<Advice>,
    pub b: Column<Advice>,
    pub out: Column<Advice>,
    pub k: Column<Fixed>,
    pub s_mul: Selector,
    pub s_add: Selector,
    pub s_add_const: Selector,
    pub s_mul_const: Selector,
    pub s_assert_const: Selector,
}

pub type Num = AssignedCell<Fr, Fr>;

pub struct ArithChip {
    config: ArithConfig,
}

impl ArithChip {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> ArithConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let out = meta.advice_column();
        let k = meta.fixed_column();
        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(out);

        let s_mul = meta.selector();
        let s_add = meta.selector();
        let s_add_const = meta.selector();
        let s_mul_const = meta.selector();
        let s_assert_const = meta.selector();

        meta.create_gate("mul: out = a * b", |meta| {
            let s = meta.query_selector(s_mul);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let out = meta.query_advice(out, Rotation::cur());
            vec![s * (a * b - out)]
        });

        meta.create_gate("add: out = a + b", |meta| {
            let s = meta.query_selector(s_add);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let out = meta.query_advice(out, Rotation::cur());
            vec![s * (a + b - out)]
        });

        meta.create_gate("add_const: out = a + k", |meta| {
            let s = meta.query_selector(s_add_const);
            let a = meta.query_advice(a, Rotation::cur());
            let k = meta.query_fixed(k, Rotation::cur());
            let out = meta.query_advice(out, Rotation::cur());
            vec![s * (a + k - out)]
        });

        meta.create_gate("mul_const: out = a * k", |meta| {
            let s = meta.query_selector(s_mul_const);
            let a = meta.query_advice(a, Rotation::cur());
            let k = meta.query_fixed(k, Rotation::cur());
            let out = meta.query_advice(out, Rotation::cur());
            vec![s * (a * k - out)]
        });

        meta.create_gate("assert_const: a == k", |meta| {
            let s = meta.query_selector(s_assert_const);
            let a = meta.query_advice(a, Rotation::cur());
            let k = meta.query_fixed(k, Rotation::cur());
            vec![s * (a - k)]
        });

        ArithConfig { a, b, out, k, s_mul, s_add, s_add_const, s_mul_const, s_assert_const }
    }

    pub fn new(config: ArithConfig) -> Self {
        Self { config }
    }

    pub fn mul(&self, mut layouter: impl Layouter<Fr>, a: &Num, b: &Num) -> Result<Num, Error> {
        layouter.assign_region(
            || "mul",
            |mut region| {
                self.config.s_mul.enable(&mut region, 0)?;
                a.copy_advice(|| "a", &mut region, self.config.a, 0)?;
                b.copy_advice(|| "b", &mut region, self.config.b, 0)?;
                let value = a.value().copied() * b.value().copied();
                region.assign_advice(|| "out", self.config.out, 0, || value)
            },
        )
    }

    pub fn add(&self, mut layouter: impl Layouter<Fr>, a: &Num, b: &Num) -> Result<Num, Error> {
        layouter.assign_region(
            || "add",
            |mut region| {
                self.config.s_add.enable(&mut region, 0)?;
                a.copy_advice(|| "a", &mut region, self.config.a, 0)?;
                b.copy_advice(|| "b", &mut region, self.config.b, 0)?;
                let value = a.value().copied() + b.value().copied();
                region.assign_advice(|| "out", self.config.out, 0, || value)
            },
        )
    }

    /// `out = a + k` — `k` is a REAL fixed-column constant, enforced by the
    /// constraint polynomial itself (not just witnessed).
    pub fn add_const(&self, mut layouter: impl Layouter<Fr>, a: &Num, k: Fr) -> Result<Num, Error> {
        layouter.assign_region(
            || "add_const",
            |mut region| {
                self.config.s_add_const.enable(&mut region, 0)?;
                a.copy_advice(|| "a", &mut region, self.config.a, 0)?;
                region.assign_fixed(|| "k", self.config.k, 0, || Value::known(k))?;
                let value = a.value().copied() + Value::known(k);
                region.assign_advice(|| "out", self.config.out, 0, || value)
            },
        )
    }

    /// `out = a * k` — same fixed-column guarantee as `add_const`.
    pub fn mul_const(&self, mut layouter: impl Layouter<Fr>, a: &Num, k: Fr) -> Result<Num, Error> {
        layouter.assign_region(
            || "mul_const",
            |mut region| {
                self.config.s_mul_const.enable(&mut region, 0)?;
                a.copy_advice(|| "a", &mut region, self.config.a, 0)?;
                region.assign_fixed(|| "k", self.config.k, 0, || Value::known(k))?;
                let value = a.value().copied() * Value::known(k);
                region.assign_advice(|| "out", self.config.out, 0, || value)
            },
        )
    }

    /// Soundly asserts `a == k` for a REAL fixed-column constant `k` —
    /// unlike comparing against a separately-witnessed cell (which a
    /// malicious prover could set to any value), this ties directly into
    /// the constraint polynomial.
    pub fn assert_const(&self, mut layouter: impl Layouter<Fr>, a: &Num, k: Fr) -> Result<(), Error> {
        layouter.assign_region(
            || "assert_const",
            |mut region| {
                self.config.s_assert_const.enable(&mut region, 0)?;
                a.copy_advice(|| "a", &mut region, self.config.a, 0)?;
                region.assign_fixed(|| "k", self.config.k, 0, || Value::known(k))?;
                Ok(())
            },
        )
    }

    pub fn load_witness(&self, mut layouter: impl Layouter<Fr>, v: Value<Fr>) -> Result<Num, Error> {
        layouter.assign_region(|| "witness", |mut region| region.assign_advice(|| "v", self.config.a, 0, || v))
    }

    pub fn assert_equal(&self, mut layouter: impl Layouter<Fr>, a: &Num, b: &Num) -> Result<(), Error> {
        layouter.assign_region(
            || "assert_equal",
            |mut region| {
                a.copy_advice(|| "a", &mut region, self.config.a, 0)?;
                b.copy_advice(|| "b", &mut region, self.config.b, 0)?;
                region.constrain_equal(a.cell(), b.cell())
            },
        )
    }

    pub fn pow5(&self, mut layouter: impl Layouter<Fr>, a: &Num) -> Result<Num, Error> {
        let a2 = self.mul(layouter.namespace(|| "a^2"), a, a)?;
        let a4 = self.mul(layouter.namespace(|| "a^4"), &a2, &a2)?;
        self.mul(layouter.namespace(|| "a^5"), &a4, a)
    }

    /// Field inversion — the prover supplies `inv` as a witness (computed
    /// off-circuit via `a.invert()`), constrained by `a * inv == 1`. This is
    /// sound: the ONLY value satisfying that multiplicative constraint is
    /// the true inverse (or the constraint is unsatisfiable if `a == 0`,
    /// which correctly makes the circuit unprovable rather than silently
    /// wrong — Baby Jubjub point addition/doubling denominators are never
    /// zero for valid curve points, by the curve's completeness property).
    pub fn invert(&self, mut layouter: impl Layouter<Fr>, a: &Num) -> Result<Num, Error> {
        let inv_value = a.value().map(|v| v.invert().unwrap());
        let inv = self.load_witness(layouter.namespace(|| "inv witness"), inv_value)?;
        let product = self.mul(layouter.namespace(|| "a * inv"), a, &inv)?;
        self.assert_const(layouter.namespace(|| "a * inv == 1"), &product, Fr::one())?;
        Ok(inv)
    }

    pub fn div(&self, mut layouter: impl Layouter<Fr>, a: &Num, b: &Num) -> Result<Num, Error> {
        let inv_b = self.invert(layouter.namespace(|| "invert b"), b)?;
        self.mul(layouter.namespace(|| "a * inv_b"), a, &inv_b)
    }

    pub fn sub(&self, mut layouter: impl Layouter<Fr>, a: &Num, b: &Num) -> Result<Num, Error> {
        let neg_b = self.mul_const(layouter.namespace(|| "-b"), b, -Fr::one())?;
        self.add(layouter.namespace(|| "a + (-b)"), a, &neg_b)
    }
}
