use crate::fields::Field256;
use crate::proofs::AssetProof;
use crate::secp256k1::{point_mul, Point};
use crate::serialization::Serialize;
use num_bigint::BigUint;
use rocksdb::DB;

pub type AssetData = (Option<Field256>, Point, BigUint);

pub trait AssetDataSource {
    /// Retrieve next asset to generate proof for
    fn next(&mut self) -> Option<AssetData>;

    /// Store the generated proof in storage
    fn put_proof(&mut self, proof: AssetProof) -> Result<(), &str>;
}

pub struct Rocks {
    db: DB,
    assets_to_generate: usize,
}

impl Rocks {
    pub fn new(assets_to_generate: usize, path: &str) -> Rocks {
        let db = DB::open_default(path).unwrap();

        Rocks {
            db,
            assets_to_generate,
        }
    }
}

impl AssetDataSource for Rocks {
    fn next(&mut self) -> Option<AssetData> {
        if self.assets_to_generate == 0 {
            return None;
        }

        self.assets_to_generate -= 1;
        let x = Field256::from(1);
        let y = point_mul(Point::g(), &x);
        let bal = BigUint::from(10u8);
        Some((Some(x), y, bal))
    }

    fn put_proof(&mut self, proof: AssetProof) -> Result<(), &str> {
        self.db
            .put(proof.y.serialize(), proof.serialize())
            .map_err(|_| "bad write")
    }
}
