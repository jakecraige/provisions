use crate::bigint::biguint_to_bits_le;
use crate::fields::Field256;
use crate::proofs::binary::BinaryProof;
use crate::secp256k1::{pedersen_commitment, point_mul, Point};
use num_bigint::BigUint;
use num_traits::identities::Zero;
use num_traits::pow::Pow;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

pub struct LiabilityProof {
    g: Point,
    h: Point,

    /// Customer Identifier
    cid: Vec<u8>,
    /// Proofs of knowledge for each bit of the balance
    bits: Vec<BinaryProof>,

    /// The fields (n, r) are considered secrets and should only be provided to the customer
    /// they relate to.

    // TODO: Should these be Field256's?
    /// Customer Identifier Salt
    n: BigUint,
    /// Summation of bit blinding factors
    pub r: BigUint,
}

const BALANCE_BITS: usize = 51;

fn compute_cid(identifier: &[u8], n: &BigUint) -> Vec<u8> {
    let mut data = identifier.to_vec();
    data.extend(n.to_bytes_be());
    Sha256::digest(&data).to_vec()
}

impl LiabilityProof {
    pub fn create(identifier: &[u8], balance: &BigUint, g: Point, h: Point) -> LiabilityProof {
        let bits = biguint_to_bits_le(balance, BALANCE_BITS);

        let initial_value = (BigUint::zero(), Vec::with_capacity(bits.len()));
        let (r, bit_proofs): (BigUint, Vec<BinaryProof>) = bits
            .par_iter()
            .enumerate()
            .fold_with(initial_value, |mut acc, (i, bit)| {
                let r_i = Field256::rand();
                let comm = BinaryProof::create(&Field256::from(*bit), &r_i, &g, &h);
                acc.0 += &r_i.value << i;
                acc.1.push(comm);
                acc
            })
            .find_first(|_| true) // Unable to find a clean way to pull out the value here
            .unwrap();

        let n = Field256::rand().value;
        let cid = compute_cid(identifier, &n);

        LiabilityProof {
            g,
            h,
            cid,
            bits: bit_proofs,
            n,
            r,
        }
    }

    /// Verify that all the binary proofd are proven.
    pub fn verify(&self) -> bool {
        // For the public verification, we simply verify that all the binary proofs are
        // correct. The customer will verify their balance individually.
        self.bits.iter().all(|bit| bit.verify())
    }

    /// Customer verification process where they confirm the balance was computed correctly
    pub fn verify_as_customer(&self, identifier: &[u8], balance: &BigUint) -> bool {
        let computed_cid = compute_cid(identifier, &self.n);
        if computed_cid != self.cid {
            return false;
        }

        // g^b * h^r
        let bal = &Field256::new(balance.clone());
        let r = &Field256::new(self.r.clone());
        let rhs = pedersen_commitment(self.g.clone(), &bal, self.h.clone(), &r);

        return self.z() == rhs;
    }

    /// Commitment to the balance as the sum of the bit commitments
    pub fn z(&self) -> Point {
        let mut z = Point::infinity();

        for (i, bit) in self.bits.iter().enumerate() {
            let exp = Field256::from(BigUint::from(2u8).pow(i));
            let z_i = point_mul(bit.l.clone(), &exp);
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
        let g = crate::g();
        let h = crate::h();
        let username = b"testuser";
        let balance = BigUint::from(10u8);

        let commitment = LiabilityProof::create(&username[..], &balance, g, h);

        assert!(commitment.verify() "commitment not able to be verified");
    }

    #[test]
    fn verify_customer_liability_commitment() {
        let g = crate::g();
        let h = crate::h();
        let username = b"testuser";
        let balance = BigUint::from(10u8);

        let commitment = LiabilityProof::create(&username[..], &balance, g, h);

        assert!(commitment.verify_as_customer(&username[..], &balance) "commitment not able to be verified");
    }
}
