use num_bigint::BigUint;
use num_traits::One;

mod field256;

pub use self::field256::Field256;

/// Find the sqrt of a value modulo p
pub fn field_sqrt(value: &BigUint, p: &BigUint) -> BigUint {
    // Only works on curves where: p % 4 = 3
    // Derived from fact that p % 4 = 3 and a^(p-1) = 1 which gives us:
    //
    // w^2 = v (we know v and are looking for w)
    // w^2 = w^2 * 1 = w^2 * w^(p-1) = w^(p+1)
    // w^(2/2) = w^(p+1)/2
    // w = w^(p+1)/2
    // w = w^2(p+1)/4 = (w^2)^(p+1)/4 = v^(p+1)/4 = w
    // let exp = (&self.p + BigUint::one()) / BigUint::from(4u8);
    let exp = (p + BigUint::one()) / BigUint::from(4u8);
    value.modpow(&exp, p)
}
