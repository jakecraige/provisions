use num_bigint::{BigInt, BigUint, Sign};
use num_integer::Integer;
use rand::rngs::OsRng;
use rand::Rng;
use secp256k1::constants::CURVE_ORDER;
use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};

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
    pub fn new(value: BigUint) -> Field256 {
        let p = Field256::p();

        Field256 {
            value: value.mod_floor(&p),
            p,
        }
    }

    /// Initialize a field element from big-endian bytes
    pub fn from_bytes_be(bytes: &[u8]) -> Field256 {
        let value = BigUint::from_bytes_be(bytes);
        Field256::new(value)
    }

    pub fn p() -> BigUint {
        BigUint::from_bytes_be(&CURVE_ORDER)
    }

    pub fn one() -> Field256 {
        Field256::new(BigUint::from(1u8))
    }

    pub fn zero() -> Field256 {
        Field256::new(BigUint::from(0u8))
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

    pub fn is_zero(&self) -> bool {
        self.value == BigUint::from(0u8)
    }

    /// True if the value is 0 or 1. False otherwise.
    pub fn is_binary(&self) -> bool {
        self.value == BigUint::from(0u8) || self.value == BigUint::from(1u8)
    }
}

impl From<BigUint> for Field256 {
    fn from(value: BigUint) -> Field256 {
        Field256::new(value)
    }
}

impl From<BigInt> for Field256 {
    fn from(value: BigInt) -> Field256 {
        let p = BigInt::from_bytes_be(Sign::Plus, &CURVE_ORDER);
        let ivalue = value.mod_floor(&p);
        let uvalue = ivalue.to_biguint().expect("no negative");
        Field256::from(uvalue)
    }
}

impl From<u8> for Field256 {
    fn from(value: u8) -> Field256 {
        Field256::new(BigUint::from(value))
    }
}

impl From<i8> for Field256 {
    fn from(value: i8) -> Field256 {
        Field256::from(BigInt::from(value))
    }
}

impl From<i32> for Field256 {
    fn from(value: i32) -> Field256 {
        Field256::from(BigInt::from(value))
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

impl<'a> Add<Field256> for &'a Field256 {
    type Output = Field256;

    fn add(self, rhs: Field256) -> Field256 {
        let value = (&self.value + rhs.value).mod_floor(&self.p);
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
        &self * rhs
    }
}

impl<'a> Mul<Field256> for &'a Field256 {
    type Output = Field256;

    fn mul(self, rhs: Field256) -> Field256 {
        self * &rhs
    }
}

impl<'a, 'b> Mul<&'a Field256> for &'b Field256 {
    type Output = Field256;

    fn mul(self, rhs: &'a Field256) -> Field256 {
        let value = (&self.value * &rhs.value).mod_floor(&self.p);
        Field256::new(value)
    }
}

impl Neg for Field256 {
    type Output = Field256;

    fn neg(self) -> Field256 {
        let value = self.p - self.value;
        Field256::new(value)
    }
}

impl Sub<Field256> for Field256 {
    type Output = Field256;

    fn sub(self, rhs: Field256) -> Field256 {
        self - &rhs
    }
}

impl<'a> Sub<&'a Field256> for Field256 {
    type Output = Field256;

    fn sub(self, rhs: &'a Field256) -> Field256 {
        &self - rhs
    }
}

impl<'a, 'b> Sub<&'a Field256> for &'b Field256 {
    type Output = Field256;

    fn sub(self, rhs: &'a Field256) -> Field256 {
        if rhs.value < self.value {
            let value = &self.value - &rhs.value;
            Field256::new(value)
        } else {
            let neg_overflow = &rhs.value - &self.value;
            let value = &self.p - neg_overflow;
            Field256::new(value)
        }
    }
}

impl fmt::Display for Field256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.value.to_str_radix(16))
    }
}
