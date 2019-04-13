use crate::fields::Field256;
use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};
use secp256k1::{All, PublicKey, Secp256k1};

#[derive(Clone, PartialEq)]
pub struct Point {
    pk: PublicKey,
    secp256k1: Secp256k1<All>,
}

impl Point {
    /// Initialize the base generator of the Secp256k1 curve
    pub fn g() -> Point {
        let mut g_bytes = Vec::with_capacity(65);
        g_bytes.push(0x04);
        g_bytes.extend_from_slice(&GENERATOR_X);
        g_bytes.extend_from_slice(&GENERATOR_Y);
        let g = PublicKey::from_slice(&g_bytes).expect("valid");

        Point::from(g)
    }

    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        self.pk.serialize_uncompressed()
    }

    /// Multiply the point by a scalar value.
    pub fn mul(&mut self, n: &Field256) -> &mut Point {
        self.pk
            .mul_assign(&self.secp256k1, &n.to_big_endian())
            .expect("invalid multiplication");
        self
    }

    /// Add the point to another point.
    pub fn add(&mut self, other: &Point) -> &mut Point {
        self.pk = self.pk.combine(&other.pk).expect("invalid addition");
        self
    }
}

impl From<PublicKey> for Point {
    fn from(pk: PublicKey) -> Point {
        Point {
            pk,
            secp256k1: Secp256k1::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_is_correct() {
        let g_ser = Point::g().serialize_uncompressed();

        assert_eq!(
            g_ser.to_vec(),
            vec![
                // marker
                0x04, // x
                0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87,
                0x0B, 0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B,
                0x16, 0xF8, 0x17, 0x98, // y
                0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11,
                0x08, 0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F,
                0xFB, 0x10, 0xD4, 0xB8,
            ]
        );
    }
}
