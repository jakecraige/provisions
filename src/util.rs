/// Whether or not the bit at the provided index is 1
fn is_bit_set(index: u8, byte: u8) -> bool {
    (byte & (1 << index)) > 0
}

/// Return the bit value at the provided index
fn bit_at_index(index: u8, byte: u8) -> u8 {
    if is_bit_set(index, byte) {
        1
    } else {
        0
    }
}

/// Convert a byte into a vector of bits in little endian
pub fn byte_to_bits_le(byte: u8) -> Vec<u8> {
    vec![
        bit_at_index(0, byte),
        bit_at_index(1, byte),
        bit_at_index(2, byte),
        bit_at_index(3, byte),
        bit_at_index(4, byte),
        bit_at_index(5, byte),
        bit_at_index(6, byte),
        bit_at_index(7, byte),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_to_bits() {
        assert_eq!(byte_to_bits_le(0), vec![0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(byte_to_bits_le(1), vec![1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(byte_to_bits_le(2), vec![0, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(byte_to_bits_le(255), vec![1, 1, 1, 1, 1, 1, 1, 1]);
    }
}
