use crate::fields::Field256;
use crate::secp256k1::Point;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

mod asset;
mod binary;
mod liability;
mod schnorr;
mod solvency;

pub use self::asset::AssetProof;
pub use self::liability::LiabilityProof;
pub use self::solvency::SolvencyProof;

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
        let p1 = crate::g();
        let p2 = crate::h();

        assert_eq!(compute_challenge(&[&p1]), compute_challenge(&[&p1]));
        assert_eq!(
            compute_challenge(&[&p1, &p2]),
            compute_challenge(&[&p1, &p2])
        );
        assert_ne!(compute_challenge(&[&p1]), compute_challenge(&[&p2]));
        assert_ne!(compute_challenge(&[&p1]), compute_challenge(&[&p1, &p2]));
    }
}
