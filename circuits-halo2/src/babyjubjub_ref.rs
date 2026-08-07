//! Pure-Rust (off-circuit) reference implementation of Baby Jubjub point
//! arithmetic and EdDSA-Poseidon verification, matching
//! circomlib/circuits/eddsaposeidon.circom + babyjub.circom EXACTLY
//! (including the "R8 + h*(8*A)" equation — NOT "R8 + h*A"; circomlib
//! multiplies A by 8 first via three doublings, both to land in the prime-
//! order subgroup and as part of the actual signature equation. Getting
//! this factor of 8 right matters for genuine parity with
//! `channel_state.circom` — an earlier, unrelated Schnorr-style scheme used
//! elsewhere in this repo for on-chain key-ownership checks — see
//! `contracts/src/BabyJubJub.sol` — deliberately does NOT use this exact
//! equation, so don't conflate the two).

use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;

pub const A_COEFF_STR: &str = "168700";
pub const D_COEFF_STR: &str = "168696";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    pub x: Fr,
    pub y: Fr,
}

impl Point {
    pub fn identity() -> Self {
        Point { x: Fr::zero(), y: Fr::one() }
    }

}

fn a_coeff() -> Fr {
    Fr::from(168700u64)
}
fn d_coeff() -> Fr {
    Fr::from(168696u64)
}

/// Twisted Edwards affine addition (also correct for doubling / identity).
pub fn point_add(p1: Point, p2: Point) -> Point {
    let a = a_coeff();
    let d = d_coeff();
    let x1y2 = p1.x * p2.y;
    let y1x2 = p1.y * p2.x;
    let y1y2 = p1.y * p2.y;
    let x1x2 = p1.x * p2.x;
    let dx1x2y1y2 = d * x1x2 * y1y2;

    let x_num = x1y2 + y1x2;
    let x_den = Fr::one() + dx1x2y1y2;
    let y_num = y1y2 - a * x1x2;
    let y_den = Fr::one() - dx1x2y1y2;

    Point { x: x_num * x_den.invert().unwrap(), y: y_num * y_den.invert().unwrap() }
}

pub fn point_double(p: Point) -> Point {
    point_add(p, p)
}

/// Scalar multiplication via double-and-add, `scalar` given as a little-
/// endian bit vector (matches how the circuit will consume it).
pub fn scalar_mul_bits(p: Point, bits: &[bool]) -> Point {
    let mut acc = Point::identity();
    let mut base = p;
    for &bit in bits {
        if bit {
            acc = point_add(acc, base);
        }
        base = point_double(base);
    }
    acc
}

pub fn fr_to_le_bits(x: Fr, n: usize) -> Vec<bool> {
    let repr = x.to_repr();
    let bytes: &[u8] = repr.as_ref();
    (0..n).map(|i| (bytes[i / 8] >> (i % 8)) & 1 == 1).collect()
}

/// circomlib's exact EdDSAPoseidonVerifier equation:
///   c = Poseidon5(R8x, R8y, Ax, Ay, M)
///   check: S*B8 == R8 + c*(8*A)
pub fn eddsa_poseidon_verify(a: Point, sig_r8: Point, sig_s: Fr, m: Fr) -> bool {
    let params5 = crate::poseidon_ref::PoseidonParams::t6();
    let c = crate::poseidon_ref::poseidon_hash(&params5, &[sig_r8.x, sig_r8.y, a.x, a.y, m]);

    let eight_a = point_double(point_double(point_double(a)));

    let c_bits = fr_to_le_bits(c, 254);
    let c_times_8a = scalar_mul_bits(eight_a, &c_bits);

    let rhs = point_add(sig_r8, c_times_8a);

    let s_bits = fr_to_le_bits(sig_s, 253);
    let base8 = base8_point();
    let lhs = scalar_mul_bits(base8, &s_bits);

    lhs.x == rhs.x && lhs.y == rhs.y
}

/// The SAME BASE8 point used throughout this repo (see
/// `contracts/src/BabyJubJub.sol`'s BASE8_X/BASE8_Y and
/// `circuits/circuits/channel_state.circom`'s EscalarMulFix call) —
/// decimal source values:
///   x = 5299619240641551281634865583518297030282874472190772894086521144482721001553
///   y = 16950150798460657717958625567821834550301663161624707787222815936182638968203
pub fn base8_point() -> Point {
    Point {
        x: crate::field::fr_from_str("0xbb77a6ad63e739b4eacb2e09d6277c12ab8d8010534e0b62893f3f6bb957051"),
        y: crate::field::fr_from_str("0x25797203f7a0b24925572e1cd16bf9edfce0051fb9e133774b3c257a872d7d8b"),
    }
}

#[cfg(test)]
mod cross_check {
    use super::*;
    use crate::field::fr_from_str;

    fn fr_from_dec(s: &str) -> Fr {
        // decimal -> hex via num-bigint-free manual approach not available here;
        // reuse PrimeField's from_str_vartime for decimal parsing.
        Fr::from_str_vartime(s).expect("valid decimal Fr")
    }

    #[test]
    fn matches_circomlibjs_real_signature() {
        let a = Point {
            x: fr_from_dec("6258698228857579243937097735069405513777546488206385948349971781708128047847"),
            y: fr_from_dec("2216124967747932654884761600749314631961003421499958761754620989171020525870"),
        };
        let m = Fr::from(42u64);
        let r8 = Point {
            x: fr_from_dec("1890458465386595858105526773644598110668086400448431915680788490394901785555"),
            y: fr_from_dec("7977044829226288017220032721753945580870354191300434234653263787068749911058"),
        };
        let s = fr_from_dec("651378536009074344523918848857813340075481059468851072242700972468585962691");

        assert!(eddsa_poseidon_verify(a, r8, s, m), "must accept circomlibjs's own valid signature");

        // Tamper with S — must reject.
        assert!(!eddsa_poseidon_verify(a, r8, s + Fr::one(), m), "must reject a tampered signature");

        // Tamper with the message — must reject.
        assert!(!eddsa_poseidon_verify(a, r8, s, m + Fr::one()), "must reject a signature over a different message");
        let _ = fr_from_str; // silence unused-import warning if any
    }
}
