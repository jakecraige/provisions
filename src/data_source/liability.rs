use crate::proofs::LiabilityProof;
use num_bigint::BigUint;

pub type LiabilityData = (Vec<u8>, BigUint);

pub trait LiabilityDataSource {
    /// Retrieve next liability to generate proof for
    fn next(&mut self) -> Option<LiabilityData>;

    /// Store the generated proof in storage
    fn put_proof(&mut self, proof: LiabilityProof) -> Result<(), &str>;
}
