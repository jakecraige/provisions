use num_bigint::BigUint;
use num_integer::Integer;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::constants::CURVE_ORDER;
use std::fmt;
use std::ops::{Add, Mul};

const FIELD_BYTES: usize = 32;

/// Field element of the Secp256k1 generator subgroup order.
#[derive(Debug, Clone, PartialEq)]
pub struct Field256 {
    pub value: BigUint,
    p: BigUint,
}

impl Field256 {
    /// Initialize a new element within the field. If the number is too large it will be modded
    /// into the field.
    fn new(value: BigUint) -> Field256 {
        let p = BigUint::from_bytes_be(&CURVE_ORDER);

        Field256 {
            value: value.mod_floor(&p),
            p,
        }
    }

    pub fn rand() -> Field256 {
        let mut rng = OsRng::new().expect("OsRng");
        // We generate the U256 by generating four u64s, converting them to U256 and then shifting the
        // bits before summing them up for the final output.
        //
        // Visually, the shifting and combination works like this;
        //     1111 0000 0000 0000 (r1)
        //     0000 1111 0000 0000 (r2)
        //     0000 0000 1111 0000 (r3)
        //   + 0000 0000 0000 1111 (r4)
        //   = 1111 1111 1111 1111
        let r1 = BigUint::from(rng.gen::<u64>()) << 192; // 256 - (64 * 3)
        let r2 = BigUint::from(rng.gen::<u64>()) << 128; // 256 - (64 * 2)
        let r3 = BigUint::from(rng.gen::<u64>()) << 64; // 256 - (64 * 1)
        let r4 = BigUint::from(rng.gen::<u64>());

        Field256::from(r1 + r2 + r3 + r4)
    }

    pub fn to_big_endian(&self) -> [u8; FIELD_BYTES] {
        let bytes = self.value.to_bytes_be();
        if bytes.len() > FIELD_BYTES {
            panic!("Unexpected number larger than field modulo");
        }

        let mut out = [0; FIELD_BYTES];
        // Since we use a big-endian representation and the bytes may be less than 32 long, we
        // calculate the index offset to fill in bytes in their proper place.
        let byte_offset = FIELD_BYTES - bytes.len();
        for (i, byte) in bytes.iter().enumerate() {
            out[byte_offset + i] = *byte;
        }
        out
    }
}

impl From<u32> for Field256 {
    fn from(value: u32) -> Field256 {
        Field256::new(BigUint::from(value))
    }
}

impl From<BigUint> for Field256 {
    fn from(value: BigUint) -> Field256 {
        Field256::new(value)
    }
}

impl Add<Field256> for Field256 {
    type Output = Field256;

    fn add(self, rhs: Field256) -> Field256 {
        self + &rhs
    }
}

impl<'a> Add<&'a Field256> for Field256 {
    type Output = Field256;

    fn add(self, rhs: &'a Field256) -> Field256 {
        let value = (self.value + &rhs.value).mod_floor(&self.p);
        Field256::new(value)
    }
}

impl Mul<Field256> for Field256 {
    type Output = Field256;

    fn mul(self, rhs: Field256) -> Field256 {
        self * &rhs
    }
}

impl<'a> Mul<&'a Field256> for Field256 {
    type Output = Field256;

    fn mul(self, rhs: &'a Field256) -> Field256 {
        let value = (self.value * &rhs.value).mod_floor(&self.p);
        Field256::new(BigUint::from(value))
    }
}

impl fmt::Display for Field256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value.to_str_radix(16))
    }
}
