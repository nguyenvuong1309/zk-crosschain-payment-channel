//! Pure-Rust (off-circuit) reference implementation of circomlib's
//! "optimized" Poseidon (see poseidon_opt.js — same algorithm, same
//! constants, ported 1:1 so this is bit-for-bit the same hash function).
//! Used both to compute expected witness values and as the specification
//! the in-circuit `poseidon_chip` module is checked against.

use crate::field::fr_from_str;
use halo2curves::bn256::Fr;


pub struct PoseidonParams {
    pub t: usize,
    pub n_rounds_f: usize,
    pub n_rounds_p: usize,
    pub c: Vec<Fr>,
    pub s: Vec<Fr>,
    pub m: Vec<Vec<Fr>>,
    pub p: Vec<Vec<Fr>>,
}

impl PoseidonParams {
    fn from_raw(t: usize, n_rounds_f: usize, n_rounds_p: usize, c: &[&str], s: &[&str], m: &[&[&str]], p: &[&[&str]]) -> Self {
        Self {
            t,
            n_rounds_f,
            n_rounds_p,
            c: c.iter().map(|x| fr_from_str(x)).collect(),
            s: s.iter().map(|x| fr_from_str(x)).collect(),
            m: m.iter().map(|row| row.iter().map(|x| fr_from_str(x)).collect()).collect(),
            p: p.iter().map(|row| row.iter().map(|x| fr_from_str(x)).collect()).collect(),
        }
    }

    pub fn t3() -> Self {
        use crate::poseidon_constants_t3 as k;
        Self::from_raw(k::T, k::N_ROUNDS_F, k::N_ROUNDS_P, k::C, k::S, k::M, k::P)
    }

    pub fn t6() -> Self {
        use crate::poseidon_constants_t6 as k;
        Self::from_raw(k::T, k::N_ROUNDS_F, k::N_ROUNDS_P, k::C, k::S, k::M, k::P)
    }

    pub fn t7() -> Self {
        use crate::poseidon_constants_t7 as k;
        Self::from_raw(k::T, k::N_ROUNDS_F, k::N_ROUNDS_P, k::C, k::S, k::M, k::P)
    }
}

fn pow5(a: Fr) -> Fr {
    let a2 = a.square();
    let a4 = a2.square();
    a4 * a
}

/// `inputs.len()` must equal `params.t - 1`. Mirrors poseidon_opt.js's
/// `poseidon()` function exactly (initState = 0, nOut = 1).
pub fn poseidon_hash(params: &PoseidonParams, inputs: &[Fr]) -> Fr {
    let t = params.t;
    assert_eq!(inputs.len(), t - 1, "wrong number of inputs for this Poseidon parameter set");

    let mut state: Vec<Fr> = std::iter::once(Fr::zero()).chain(inputs.iter().copied()).collect();

    // state += C[0..t]
    for i in 0..t {
        state[i] += params.c[i];
    }

    let half_f = params.n_rounds_f / 2;

    // First half of full rounds (minus the last one, which is folded into
    // the pre-sparse M/P transition below — matches poseidon_opt.js).
    for r in 0..half_f - 1 {
        for s in state.iter_mut() {
            *s = pow5(*s);
        }
        for i in 0..t {
            state[i] += params.c[(r + 1) * t + i];
        }
        state = mat_mul(&params.m, &state);
    }

    // Last full round of the first half, then switch to the P matrix.
    for s in state.iter_mut() {
        *s = pow5(*s);
    }
    for i in 0..t {
        state[i] += params.c[(half_f - 1 + 1) * t + i];
    }
    state = mat_mul(&params.p, &state);

    // Partial rounds — only state[0] gets the S-box; linear layer is the
    // sparse S-matrix trick (see poseidon_opt.js for why this is equivalent
    // to a full M multiply with the un-optimized constants).
    for r in 0..params.n_rounds_p {
        state[0] = pow5(state[0]);
        state[0] += params.c[half_f * t + t + r];

        let s0 = state.iter().enumerate().fold(Fr::zero(), |acc, (j, a)| acc + params.s[(t * 2 - 1) * r + j] * a);
        for k in 1..t {
            let contrib = state[0] * params.s[(t * 2 - 1) * r + t + k - 1];
            state[k] += contrib;
        }
        state[0] = s0;
    }

    // Second half of full rounds (minus the last).
    for r in 0..half_f - 1 {
        for s in state.iter_mut() {
            *s = pow5(*s);
        }
        for i in 0..t {
            state[i] += params.c[(half_f + 1) * t + params.n_rounds_p + r * t + i];
        }
        state = mat_mul(&params.m, &state);
    }

    // Final full round: S-box then M-multiply, no constant addition.
    for s in state.iter_mut() {
        *s = pow5(*s);
    }
    state = mat_mul(&params.m, &state);

    state[0]
}

fn mat_mul(mat: &[Vec<Fr>], state: &[Fr]) -> Vec<Fr> {
    let t = state.len();
    (0..t)
        .map(|i| (0..t).fold(Fr::zero(), |acc, j| acc + mat[j][i] * state[j]))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t3_is_deterministic_and_nonzero() {
        let params = PoseidonParams::t3();
        let h = poseidon_hash(&params, &[Fr::one(), Fr::from(2u64)]);
        assert_ne!(h, Fr::zero());
        let h2 = poseidon_hash(&params, &[Fr::one(), Fr::from(2u64)]);
        assert_eq!(h, h2);
        let h3 = poseidon_hash(&params, &[Fr::from(2u64), Fr::one()]);
        assert_ne!(h, h3, "hash must depend on input order");
    }
}

#[cfg(test)]
mod cross_check {
    use super::*;

    #[test]
    fn matches_circomlibjs_reference() {
        let params = PoseidonParams::t3();
        let h = poseidon_hash(&params, &[Fr::one(), Fr::from(2u64)]);
        // circomlibjs: poseidon([1n, 2n]) == 7853200120776062878684798364095072458815029376092732009249414926327459813530
        let expected = fr_from_str("0x115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
        assert_eq!(h, expected, "Poseidon(t=3) must match circomlibjs bit-for-bit");
    }
}

#[cfg(test)]
mod cross_check_t6_t7 {
    use super::*;

    #[test]
    fn t6_matches_circomlibjs() {
        let params = PoseidonParams::t6();
        let inputs: Vec<Fr> = (1u64..=5).map(Fr::from).collect();
        let h = poseidon_hash(&params, &inputs);
        let expected = fr_from_str("0xdab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0");
        assert_eq!(h, expected, "Poseidon(t=6) must match circomlibjs bit-for-bit");
    }

    #[test]
    fn t7_matches_circomlibjs() {
        let params = PoseidonParams::t7();
        let inputs: Vec<Fr> = (1u64..=6).map(Fr::from).collect();
        let h = poseidon_hash(&params, &inputs);
        let expected = fr_from_str("0x2d1a03850084442813c8ebf094dea47538490a68b05f2239134a4cca2f6302e1");
        assert_eq!(h, expected, "Poseidon(t=7) must match circomlibjs bit-for-bit");
    }
}
