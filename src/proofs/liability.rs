use crate::bigint::{biguint_to_bits_le, biguint_to_bytes_be};
use crate::fields::Field256;
use crate::proofs::binary::BinaryProof;
use crate::secp256k1::{pedersen_commitment, point_mul, Point};
use crate::serialization::{Deserialize, Serialize};
use num_bigint::BigUint;
use num_traits::identities::Zero;
use num_traits::pow::Pow;
use rayon::prelude::*;
use sha2::{Digest, Sha256};

pub struct LiabilityProof {
    g: Point,
    h: Point,

    /// Customer Identifier
    cid: [u8; 32],
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

fn compute_cid(identifier: &[u8], n: &BigUint) -> [u8; 32] {
    let mut data = identifier.to_vec();
    data.extend(n.to_bytes_be());
    let digest = Sha256::digest(&data);
    let mut out = [0; 32];
    out.copy_from_slice(&digest[..]);
    out
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
            .reduce_with(|mut acc, (partial_total, bits)| {
                acc.0 += partial_total;
                acc.1.extend(bits);
                acc
            })
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

impl Serialize for LiabilityProof {
    /// Encodes into 32 + (261 * 51) + 39 = 13,382 bytes
    fn serialize(&self) -> Vec<u8> {
        let mut out = vec![];
        out.extend(&self.cid.clone());
        out.extend(
            self.bits
                .iter()
                .map(|bit| bit.serialize())
                .flatten()
                .collect::<Vec<u8>>(),
        );
        out.extend(biguint_to_bytes_be(&self.n, 32));
        out.extend(self.r.to_bytes_be()); // variable length
        out
    }
}

impl Deserialize for LiabilityProof {
    fn deserialize(bytes: &[u8]) -> LiabilityProof {
        let (g, h) = (crate::g(), crate::h());
        let mut cid = [0; 32];
        cid.copy_from_slice(&bytes[0..32]);
        let bits = bytes[32..(32 + (261 * 51))]
            .chunks(261)
            .map(|proof_bytes| BinaryProof::deserialize(proof_bytes))
            .collect::<Vec<BinaryProof>>();
        let n = BigUint::from_bytes_be(&bytes[13343..13375]);
        let r = BigUint::from_bytes_be(&bytes[13375..]);

        LiabilityProof {
            g,
            h,
            cid,
            bits,
            n,
            r,
        }
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

    #[test]
    fn liability_proof_serialization() {
        let g = crate::g();
        let h = crate::h();
        let username = b"testuser";
        let balance = BigUint::from(10u8);

        let proof = LiabilityProof::create(&username[..], &balance, g, h);
        let proof2 = LiabilityProof::deserialize(&proof.serialize());
    }
}
