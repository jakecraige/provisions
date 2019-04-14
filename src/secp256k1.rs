use crate::fields::Field256;
use num_bigint::BigUint;
use secp256k1::constants::{GENERATOR_X, GENERATOR_Y};
use secp256k1::{All, PublicKey, Secp256k1};
use std::fmt;

#[derive(Clone, PartialEq, Debug)]
pub struct Point {
    pk: PublicKey,
    secp256k1: Secp256k1<All>,
    infinity: bool,
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

    pub fn infinity() -> Point {
        let mut out = Point::g();
        out.infinity = true;
        out
    }

    pub fn serialize_uncompressed(&self) -> [u8; 65] {
        self.pk.serialize_uncompressed()
    }

    /// Multiply the point by a scalar value.
    pub fn mul(&mut self, n: &Field256) -> &mut Point {
        if n.is_zero() {
            self.infinity = true
        } else {
            if self.infinity {
                // Multiplying infinity by n is a noop
            } else {
                self.pk
                    .mul_assign(&self.secp256k1, &n.to_big_endian())
                    .expect("invalid multiplication");
            }
        }
        self
    }

    /// Add the point to another point.
    pub fn add(&mut self, other: &Point) -> &mut Point {
        if self.infinity {
            // 0 + Q = Q or 0 + 0 = 0
            self.pk = other.pk;
            self.infinity = other.infinity;
        } else if other.infinity {
            // P + O = P
            // Noop
        } else {
            // P + Q = R
            self.pk = self.pk.combine(&other.pk).expect("invalid addition");
            self.infinity = false;
        }
        self
    }

    /// Subtract one point from the other
    pub fn sub(&mut self, other: &Point) -> &mut Point {
        self.add(&other.inverse())
    }

    /// Return the additive inverse of the point. -P where P + -P = 0
    pub fn inverse(&self) -> Point {
        // The secp256k1 library doesn't provide raw access to the coordinates or allow
        // initializing from them directly. So to flip the y coordinate we need to serialize it,
        // parse the y coordinate and flip it, update the serialized version, an initialize a new
        // point.
        let mut sec = self.serialize_uncompressed();
        println!("{:?}", sec[33..].to_vec());
        let y = Field256::from_bytes_be(&sec[33..]);
        println!("{:?}", y.to_big_endian());
        let y_inv = (-y).to_big_endian();
        for i in 0..y_inv.len() {
            sec[33 + i] = y_inv[i];
        }
        let new_point = PublicKey::from_slice(&sec).expect("point to be valid");

        Point {
            pk: new_point,
            secp256k1: Secp256k1::new(),
            infinity: false,
        }
    }
}

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.infinity {
            write!(f, "(inf, inf)")
        } else {
            let bytes = self.serialize_uncompressed();
            let x = BigUint::from_bytes_be(&bytes[1..33]);
            let y = BigUint::from_bytes_be(&bytes[33..65]);
            write!(f, "({}, {})", x.to_str_radix(16), y.to_str_radix(16))
        }
    }
}

impl From<PublicKey> for Point {
    fn from(pk: PublicKey) -> Point {
        Point {
            pk,
            secp256k1: Secp256k1::new(),
            infinity: false,
        }
    }
}

// Create commitment of y = g^x * h^r
pub fn pedersen_commitment(g: Point, x: &Field256, h: Point, r: &Field256) -> Point {
    let mut gx = point_mul(g, x);
    let hr = point_mul(h, r);

    gx.add(&hr);
    gx
}

// Point mul g^x
pub fn point_mul(g: Point, x: &Field256) -> Point {
    let mut gx = g;
    gx.mul(&x);
    gx
}

/// g * h
pub fn point_add(mut g: Point, h: &Point) -> Point {
    g.add(h);
    g
}

/// g^x * h
pub fn point_mul_add(g: Point, x: &Field256, h: &Point) -> Point {
    point_add(point_mul(g, x), h)
}

/// n_0 * n_1 * ... * n_len
pub fn point_sum(points: &[&Point]) -> Point {
    let mut out = Point::infinity();

    for point in points.iter() {
        out.add(point);
    }

    out
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
