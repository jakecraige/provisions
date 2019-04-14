use crate::util::byte_to_bits_le;
use num_bigint::BigUint;
use std::iter::repeat;

/// return the value as a vector of its bits up to len
pub fn biguint_to_bits_le(value: &BigUint, len: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut bits: Vec<u8> = bytes
        .iter()
        .flat_map(|byte| byte_to_bits_le(*byte))
        .take(len)
        .collect();

    if bits.len() < len {
        let padding: Vec<u8> = repeat(0).take(len - bits.len()).collect();
        bits.extend(padding);
    }

    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biguint_to_bits_le() {
        let value = BigUint::from(1u8);

        assert_eq!(biguint_to_bits_le(&BigUint::from(1u8), 4), vec![1, 0, 0, 0]);
        assert_eq!(
            biguint_to_bits_le(&BigUint::from(1u8), 8),
            vec![1, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            biguint_to_bits_le(&BigUint::from(43690u16), 16),
            vec![0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1]
        );
    }
}
