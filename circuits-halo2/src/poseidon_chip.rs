//! In-circuit Poseidon — mirrors `poseidon_ref::poseidon_hash` operation-
//! for-operation (same round structure, same constants), just built from
//! `ArithChip` gate calls instead of raw field arithmetic, so every
//! intermediate value is constrained rather than merely computed.

use crate::chip::{ArithChip, Num};
use crate::field::fr_from_str;
use crate::poseidon_ref::PoseidonParams;
use halo2_proofs::circuit::Layouter;
use halo2_proofs::plonk::Error;
use halo2curves::bn256::Fr;

pub fn poseidon_hash_circuit(
    chip: &ArithChip,
    mut layouter: impl Layouter<Fr>,
    params: &PoseidonParams,
    inputs: &[Num],
) -> Result<Num, Error> {
    let t = params.t;
    assert_eq!(inputs.len(), t - 1);

    let zero = chip.load_witness(layouter.namespace(|| "zero"), halo2_proofs::circuit::Value::known(Fr::zero()))?;
    let mut state: Vec<Num> = std::iter::once(zero).chain(inputs.iter().cloned()).collect();

    for i in 0..t {
        state[i] = chip.add_const(layouter.namespace(|| "init C"), &state[i], params.c[i])?;
    }

    let half_f = params.n_rounds_f / 2;

    for r in 0..half_f - 1 {
        for s in state.iter_mut() {
            *s = chip.pow5(layouter.namespace(|| "pow5"), s)?;
        }
        for i in 0..t {
            state[i] = chip.add_const(layouter.namespace(|| "C"), &state[i], params.c[(r + 1) * t + i])?;
        }
        state = mat_mul(chip, layouter.namespace(|| "M"), &params.m, &state)?;
    }

    for s in state.iter_mut() {
        *s = chip.pow5(layouter.namespace(|| "pow5"), s)?;
    }
    for i in 0..t {
        state[i] = chip.add_const(layouter.namespace(|| "C"), &state[i], params.c[(half_f - 1 + 1) * t + i])?;
    }
    state = mat_mul(chip, layouter.namespace(|| "P"), &params.p, &state)?;

    for r in 0..params.n_rounds_p {
        state[0] = chip.pow5(layouter.namespace(|| "pow5"), &state[0])?;
        state[0] = chip.add_const(layouter.namespace(|| "C"), &state[0], params.c[half_f * t + t + r])?;

        let mut s0 = chip.mul_const(layouter.namespace(|| "s0 term"), &state[0], params.s[(t * 2 - 1) * r])?;
        for j in 1..t {
            let term = chip.mul_const(layouter.namespace(|| "s0 term"), &state[j], params.s[(t * 2 - 1) * r + j])?;
            s0 = chip.add(layouter.namespace(|| "s0 acc"), &s0, &term)?;
        }
        for k in 1..t {
            let contrib = chip.mul_const(layouter.namespace(|| "contrib"), &state[0], params.s[(t * 2 - 1) * r + t + k - 1])?;
            state[k] = chip.add(layouter.namespace(|| "state[k] += contrib"), &state[k], &contrib)?;
        }
        state[0] = s0;
    }

    for r in 0..half_f - 1 {
        for s in state.iter_mut() {
            *s = chip.pow5(layouter.namespace(|| "pow5"), s)?;
        }
        for i in 0..t {
            state[i] = chip.add_const(layouter.namespace(|| "C"), &state[i], params.c[(half_f + 1) * t + params.n_rounds_p + r * t + i])?;
        }
        state = mat_mul(chip, layouter.namespace(|| "M"), &params.m, &state)?;
    }

    for s in state.iter_mut() {
        *s = chip.pow5(layouter.namespace(|| "pow5"), s)?;
    }
    state = mat_mul(chip, layouter.namespace(|| "M final"), &params.m, &state)?;

    Ok(state[0].clone())
}

fn mat_mul(chip: &ArithChip, mut layouter: impl Layouter<Fr>, mat: &[Vec<Fr>], state: &[Num]) -> Result<Vec<Num>, Error> {
    let t = state.len();
    let mut out = Vec::with_capacity(t);
    for i in 0..t {
        let mut acc = chip.mul_const(layouter.namespace(|| "mat term 0"), &state[0], mat[0][i])?;
        for j in 1..t {
            let term = chip.mul_const(layouter.namespace(|| "mat term"), &state[j], mat[j][i])?;
            acc = chip.add(layouter.namespace(|| "mat acc"), &acc, &term)?;
        }
        out.push(acc);
    }
    Ok(out)
}

#[allow(dead_code)]
fn _unused() -> Fr {
    fr_from_str("0x01")
}
