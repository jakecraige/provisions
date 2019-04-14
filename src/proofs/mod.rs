use crate::fields::Field256;
use crate::secp256k1::Point;
use num_bigint::BigUint;
use sha2::{Digest as Sha2Digest, Sha256};

mod binary_commitment;
mod liability;
mod schnorr;

/// Compute a challenge value from a set of points using the Fiat-Shamir heuristic
fn compute_challenge(points: &[&Point]) -> Field256 {
    let mut hasher = Sha256::new();
    for point in points {
        hasher.input(&point.serialize_uncompressed()[..]);
    }
    let result = hasher.result();
    Field256::from(BigUint::from_bytes_be(result.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_deterministic() {
        let p1 = Point::g();
        let mut p2 = Point::g();
        p2.mul(&Field256::from(2));

        assert_eq!(compute_challenge(&[&p1]), compute_challenge(&[&p1]));
        assert_eq!(
            compute_challenge(&[&p1, &p2]),
            compute_challenge(&[&p1, &p2])
        );
        assert_ne!(compute_challenge(&[&p1]), compute_challenge(&[&p2]));
        assert_ne!(compute_challenge(&[&p1]), compute_challenge(&[&p1, &p2]));
    }
}
