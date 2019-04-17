use crate::data_source::liability::LiabilityDataSource;
use crate::proofs::LiabilityProof;
use crate::secp256k1::Point;

pub struct LiabilityProofBuilder<'a> {
    ds: &'a mut LiabilityDataSource,
    g: Point,
    h: Point,
}

impl<'a> LiabilityProofBuilder<'a> {
    pub fn new(ds: &'a mut LiabilityDataSource) -> LiabilityProofBuilder {
        LiabilityProofBuilder {
            ds,
            g: crate::g(),
            h: crate::h(),
        }
    }

    pub fn build(&mut self) {
        loop {
            match self.ds.next() {
                None => break,

                Some(liab) => {
                    let proof =
                        LiabilityProof::create(&liab.0, &liab.1, self.g.clone(), self.h.clone());
                    self.ds.put_proof(proof).expect("put works");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_source::liability::LiabilityData;
    use crate::fields::Field256;
    use num_bigint::BigUint;

    #[test]
    fn liability_proof_builder_builds_all_liabilitys() {
        let liability_count = 2;
        let liabilitys = gen_liabilitys(liability_count);
        let mut liability_ds = MemoryLiabilityDataSource::new(liabilitys);
        let mut builder = LiabilityProofBuilder::new(&mut liability_ds);

        builder.build();

        assert_eq!(liability_ds.liabilitys.len(), 0);
        assert_eq!(liability_ds.proofs.len(), liability_count);
    }

    fn gen_liabilitys(num: usize) -> Vec<LiabilityData> {
        (0..num)
            .into_iter()
            .map(|_| {
                let id = Field256::rand().to_bytes_be().to_vec();
                let bal = BigUint::from(10u8);
                (id, bal)
            })
            .collect()
    }

    struct MemoryLiabilityDataSource {
        liabilitys: Vec<LiabilityData>,
        proofs: Vec<LiabilityProof>,
    }

    impl MemoryLiabilityDataSource {
        fn new(liabilitys: Vec<LiabilityData>) -> MemoryLiabilityDataSource {
            MemoryLiabilityDataSource {
                liabilitys,
                proofs: vec![],
            }
        }
    }

    impl LiabilityDataSource for MemoryLiabilityDataSource {
        fn next(&mut self) -> Option<LiabilityData> {
            if self.liabilitys.len() > 0 {
                let liability = self.liabilitys.remove(0);
                Some(liability)
            } else {
                None
            }
        }

        fn put_proof(&mut self, proof: LiabilityProof) -> Result<(), &str> {
            self.proofs.push(proof);
            Ok(())
        }
    }
}
