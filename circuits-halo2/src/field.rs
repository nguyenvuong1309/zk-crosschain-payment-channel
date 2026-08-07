//! Helper to parse the hex/decimal string constants (extracted from
//! circomlibjs) into `halo2curves::bn256::Fr` field elements.

use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;

/// Parses a `0x...`-prefixed hex string (as circomlibjs emits) into an Fr
/// element. Panics on malformed input — these are compile-time-known
/// constants, not user input.
pub fn fr_from_str(s: &str) -> Fr {
    let s = s.strip_prefix("0x").expect("constant must be 0x-prefixed hex");
    let bytes = hex_to_le_bytes32(s);
    Fr::from_repr(bytes).expect("constant must be a valid Fr element")
}

fn hex_to_le_bytes32(hex: &str) -> [u8; 32] {
    let hex = if hex.len() % 2 == 1 { format!("0{hex}") } else { hex.to_string() };
    let mut be = vec![0u8; 32 - hex.len() / 2];
    for i in (0..hex.len()).step_by(2) {
        be.push(u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex digit"));
    }
    assert_eq!(be.len(), 32, "constant exceeds 256 bits");
    let mut le = [0u8; 32];
    for (i, b) in be.iter().rev().enumerate() {
        le[i] = *b;
    }
    le
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_known_value() {
        // 1 in hex, LE-encoded — sanity check the byte-order handling.
        let one = fr_from_str("0x01");
        assert_eq!(one, Fr::one());
    }
}
