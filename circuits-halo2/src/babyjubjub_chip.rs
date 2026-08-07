//! In-circuit Baby Jubjub point arithmetic — mirrors `babyjubjub_ref.rs`
//! operation-for-operation, built from `ArithChip` gate calls.

use crate::chip::{ArithChip, Num};
use halo2_proofs::circuit::{Layouter, Value};
use halo2_proofs::plonk::Error;
use halo2curves::bn256::Fr;

#[derive(Clone)]
pub struct PointNum {
    pub x: Num,
    pub y: Num,
}

fn a_coeff() -> Fr {
    Fr::from(168700u64)
}
fn d_coeff() -> Fr {
    Fr::from(168696u64)
}

/// Twisted Edwards affine addition (also correct for doubling / identity) —
/// same formula as `babyjubjub_ref::point_add`.
pub fn point_add(chip: &ArithChip, mut layouter: impl Layouter<Fr>, p1: &PointNum, p2: &PointNum) -> Result<PointNum, Error> {
    let x1y2 = chip.mul(layouter.namespace(|| "x1y2"), &p1.x, &p2.y)?;
    let y1x2 = chip.mul(layouter.namespace(|| "y1x2"), &p1.y, &p2.x)?;
    let y1y2 = chip.mul(layouter.namespace(|| "y1y2"), &p1.y, &p2.y)?;
    let x1x2 = chip.mul(layouter.namespace(|| "x1x2"), &p1.x, &p2.x)?;
    let x1x2y1y2 = chip.mul(layouter.namespace(|| "x1x2y1y2"), &x1x2, &y1y2)?;
    let dx1x2y1y2 = chip.mul_const(layouter.namespace(|| "d*.."), &x1x2y1y2, d_coeff())?;

    let x_num = chip.add(layouter.namespace(|| "x_num"), &x1y2, &y1x2)?;
    let x_den = chip.add_const(layouter.namespace(|| "x_den"), &dx1x2y1y2, Fr::one())?;

    let a_x1x2 = chip.mul_const(layouter.namespace(|| "a*x1x2"), &x1x2, a_coeff())?;
    let y_num = chip.sub(layouter.namespace(|| "y_num"), &y1y2, &a_x1x2)?;
    let neg_dx1x2y1y2 = chip.mul_const(layouter.namespace(|| "-d*.."), &dx1x2y1y2, -Fr::one())?;
    let y_den = chip.add_const(layouter.namespace(|| "y_den"), &neg_dx1x2y1y2, Fr::one())?;

    let x = chip.div(layouter.namespace(|| "x3"), &x_num, &x_den)?;
    let y = chip.div(layouter.namespace(|| "y3"), &y_num, &y_den)?;
    Ok(PointNum { x, y })
}

pub fn point_double(chip: &ArithChip, layouter: impl Layouter<Fr>, p: &PointNum) -> Result<PointNum, Error> {
    point_add(chip, layouter, p, p)
}

pub fn identity(chip: &ArithChip, mut layouter: impl Layouter<Fr>) -> Result<PointNum, Error> {
    let x = chip.load_witness(layouter.namespace(|| "id.x"), Value::known(Fr::zero()))?;
    let y = chip.load_witness(layouter.namespace(|| "id.y"), Value::known(Fr::one()))?;
    Ok(PointNum { x, y })
}

/// Decomposes `value` into `n` witnessed LE bits, constrained to be boolean
/// AND to sum (weighted by powers of 2) back to `value` — WITHOUT this
/// second check, a malicious prover could supply arbitrary boolean "bits"
/// unrelated to the real scalar, completely defeating the signature check
/// downstream. `bits_hint` are the actual bit values (computed off-circuit)
/// used to build the witness.
pub fn to_bits(chip: &ArithChip, mut layouter: impl Layouter<Fr>, value: &Num, n: usize, bits_hint: &[bool]) -> Result<Vec<Num>, Error> {
    assert_eq!(bits_hint.len(), n);
    let mut bits = Vec::with_capacity(n);
    for &b in bits_hint {
        let cell = chip.load_witness(layouter.namespace(|| "bit"), Value::known(if b { Fr::one() } else { Fr::zero() }))?;
        // Booleanity: b*b == b.
        let bb = chip.mul(layouter.namespace(|| "b*b"), &cell, &cell)?;
        chip.assert_equal(layouter.namespace(|| "b*b == b"), &bb, &cell)?;
        bits.push(cell);
    }

    // sum_i bits[i] * 2^i must equal `value`.
    let mut acc = chip.mul_const(layouter.namespace(|| "bit0 * 1"), &bits[0], Fr::one())?;
    let mut pow2 = Fr::from(2u64);
    for bit in bits.iter().skip(1) {
        let term = chip.mul_const(layouter.namespace(|| "bit * 2^i"), bit, pow2)?;
        acc = chip.add(layouter.namespace(|| "acc"), &acc, &term)?;
        pow2 = pow2.double();
    }
    chip.assert_equal(layouter.namespace(|| "bit decomposition == value"), &acc, value)?;

    Ok(bits)
}

/// Conditional select: `out = if bit==1 { on } else { off }`, expressed as
/// `off + bit*(on - off)` — sound because `bit` was already constrained
/// boolean by `to_bits`.
fn select(chip: &ArithChip, mut layouter: impl Layouter<Fr>, bit: &Num, on: &Num, off: &Num) -> Result<Num, Error> {
    let diff = chip.sub(layouter.namespace(|| "on - off"), on, off)?;
    let scaled = chip.mul(layouter.namespace(|| "bit * diff"), bit, &diff)?;
    chip.add(layouter.namespace(|| "off + bit*diff"), &off, &scaled)
}

fn select_point(chip: &ArithChip, mut layouter: impl Layouter<Fr>, bit: &Num, on: &PointNum, off: &PointNum) -> Result<PointNum, Error> {
    let x = select(chip, layouter.namespace(|| "select x"), bit, &on.x, &off.x)?;
    let y = select(chip, layouter.namespace(|| "select y"), bit, &on.y, &off.y)?;
    Ok(PointNum { x, y })
}

/// Double-and-add scalar multiplication using pre-decomposed LE bits (see
/// `to_bits`) — mirrors `babyjubjub_ref::scalar_mul_bits`.
pub fn scalar_mul_bits(chip: &ArithChip, mut layouter: impl Layouter<Fr>, p: &PointNum, bits: &[Num]) -> Result<PointNum, Error> {
    let mut acc = identity(chip, layouter.namespace(|| "acc = identity"))?;
    let mut base = p.clone();
    for bit in bits {
        let added = point_add(chip, layouter.namespace(|| "acc + base"), &acc, &base)?;
        acc = select_point(chip, layouter.namespace(|| "select acc"), bit, &added, &acc)?;
        base = point_double(chip, layouter.namespace(|| "double base"), &base)?;
    }
    Ok(acc)
}
