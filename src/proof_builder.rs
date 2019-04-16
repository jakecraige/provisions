use crate::data_source::asset::AssetDataSource;
use crate::proofs::AssetProof;
use crate::secp256k1::Point;

pub struct ProofBuilder<'a> {
    asset_ds: &'a mut AssetDataSource,
    g: Point,
    h: Point,
}

impl<'a> ProofBuilder<'a> {
    pub fn new(asset_ds: &'a mut AssetDataSource) -> ProofBuilder {
        ProofBuilder {
            asset_ds,
            g: crate::g(),
            h: crate::h(),
        }
    }

    pub fn build(&mut self) {
        loop {
            match self.asset_ds.next_asset() {
                None => break,

                Some(asset) => {
                    let proof = AssetProof::create(asset.0, &asset.1, asset.2, &self.g, &self.h);
                    self.asset_ds.put_proof(proof).expect("put works");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_source::asset::AssetData;
    use crate::fields::Field256;
    use crate::secp256k1::{point_mul, Point};
    use num_bigint::BigUint;

    #[test]
    fn proof_builder_builds_all_assets() {
        let asset_count = 2;
        let assets = gen_assets(asset_count);
        let mut asset_ds = MemoryAssetDataSource::new(assets);
        let mut builder = ProofBuilder::new(&mut asset_ds);

        builder.build();

        assert_eq!(asset_ds.assets.len(), 0);
        assert_eq!(asset_ds.proofs.len(), asset_count);
    }

    fn gen_assets(num: usize) -> Vec<AssetData> {
        (0..num)
            .into_iter()
            .map(|_| {
                let x = Field256::from(1);
                let y = point_mul(Point::g(), &x);
                let bal = BigUint::from(10u8);
                (Some(x), y, bal)
            })
            .collect()
    }

    struct MemoryAssetDataSource {
        assets: Vec<AssetData>,
        proofs: Vec<AssetProof>,
    }

    impl MemoryAssetDataSource {
        fn new(assets: Vec<AssetData>) -> MemoryAssetDataSource {
            MemoryAssetDataSource {
                assets,
                proofs: vec![],
            }
        }
    }

    impl AssetDataSource for MemoryAssetDataSource {
        fn next_asset(&mut self) -> Option<AssetData> {
            if self.assets.len() > 0 {
                let asset = self.assets.remove(0);
                Some(asset)
            } else {
                None
            }
        }

        fn put_proof(&mut self, proof: AssetProof) -> Result<(), &str> {
            self.proofs.push(proof);
            Ok(())
        }
    }
}
