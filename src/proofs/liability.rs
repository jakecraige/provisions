use crate::bigint::biguint_to_bits_le;
use crate::fields::Field256;
use crate::proofs::binary_commitment::BinaryCommitment;
use crate::secp256k1::Point;
use num_bigint::BigUint;
use num_traits::identities::Zero;
use num_traits::pow::Pow;
use sha2::{Digest as Sha2Digest, Sha256};

struct LiabilityCommitment {
    g: Point,
    h: Point,

    /// Customer Identifier
    cid: Vec<u8>,
    /// Commitments to each bit of the balance
    bits: Vec<BinaryCommitment>,

    /// The fields (n, r) are considered secrets and should only be provided to the customer
    /// they relate to.

    /// Customer Identifier Salt
    n: BigUint,
    /// Summation of bit blinding factors
    r: BigUint,
}

const BALANCE_BITS: usize = 51;

fn compute_cid(identifier: &[u8], n: &BigUint) -> Vec<u8> {
    let mut data = identifier.to_vec();
    data.extend(n.to_bytes_be());
    Sha256::digest(&data).to_vec()
}

impl LiabilityCommitment {
    fn create(identifier: &[u8], balance: &BigUint, g: Point, h: Point) -> LiabilityCommitment {
        let bits = biguint_to_bits_le(balance, BALANCE_BITS);
        let mut r = BigUint::zero();

        let mut bit_commitments: Vec<BinaryCommitment> = Vec::with_capacity(bits.len());
        for (i, bit) in bits.iter().enumerate() {
            let r_i = Field256::rand();
            r += &r_i.value << i;
            let comm = BinaryCommitment::create(&Field256::from(*bit), &r_i, &g, &h);
            bit_commitments.push(comm);
        }

        let n = Field256::rand().value;
        let cid = compute_cid(identifier, &n);

        LiabilityCommitment {
            g,
            h,
            cid,
            bits: bit_commitments,
            n,
            r,
        }
    }

    /// Verify that all the binary commitments are proven.
    fn verify(&self) -> bool {
        // For the public verification, we simply verify that all the binary commitments are
        // correct. The customer will verify their balance individually.
        self.bits.iter().all(|bit| bit.verify())
    }

    /// Customer verification process where they confirm the balance was computed correctly
    fn verify_as_customer(&self, identifier: &[u8], balance: &BigUint) -> bool {
        let computed_cid = compute_cid(identifier, &self.n);
        if computed_cid != self.cid {
            return false;
        }

        // g^b * h^r
        let mut gb = self.g.clone();
        gb.mul(&Field256::new(balance.clone()));
        let mut hr = self.h.clone();
        hr.mul(&Field256::new(self.r.clone()));
        let mut rhs = gb;
        rhs.add(&hr);

        return self.z() == rhs;
    }

    /// Commitment to the balance as the sum of the bit commitments
    fn z(&self) -> Point {
        let mut z = Point::infinity();

        for (i, bit) in self.bits.iter().enumerate() {
            let exp = Field256::from(BigUint::from(2u8).pow(i));
            let mut z_i = bit.l.clone();
            z_i.mul(&exp);
            z.add(&z_i);
        }

        z
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_public_liability_commitment() {
        let g = Point::g();
        let mut h = Point::g();
        h.mul(&Field256::from(2));
        let username = b"testuser";
        let balance = BigUint::from(10u8);

        let commitment = LiabilityCommitment::create(&username[..], &balance, g, h);

        assert!(commitment.verify() "commitment not able to be verified");
    }

    #[test]
    fn verify_customer_liability_commitment() {
        let g = Point::g();
        let mut h = Point::g();
        h.mul(&Field256::from(2));
        let username = b"testuser";
        let balance = BigUint::from(10u8);

        let commitment = LiabilityCommitment::create(&username[..], &balance, g, h);

        assert!(commitment.verify_as_customer(&username[..], &balance) "commitment not able to be verified");
    }
}
