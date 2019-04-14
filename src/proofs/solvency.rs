use crate::fields::Field256;
use crate::proofs::asset::AssetProof;
use crate::proofs::liability::LiabilityProof;
use crate::proofs::schnorr::SchnorrProof;
use crate::secp256k1::{point_add, point_mul, point_sum, Point};
use num_bigint::BigUint;
use num_bigint::ToBigInt;

struct SolvencyProof {
    schnorr: SchnorrProof,
}

impl SolvencyProof {
    fn create(
        asset_proofs: &[AssetProof],
        liability_proofs: &[LiabilityProof],
        h: Point,
    ) -> SolvencyProof {
        let asset_commitments: Vec<&Point> =
            asset_proofs.iter().map(|proof| proof.p_ref()).collect();
        let z_assets = point_sum(&asset_commitments);
        // TODO: This double map to get a reference to the point is pretty gross
        let liability_commitments: Vec<Point> =
            liability_proofs.iter().map(|proof| proof.z()).collect();
        let liability_commitments: Vec<&Point> =
            liability_commitments.iter().map(|comm| comm).collect();
        let z_liabilities = point_sum(&liability_commitments);

        let z_solvency = point_add(z_assets, &point_mul(z_liabilities, &Field256::from(-1)));

        let v_sum: BigUint = asset_proofs.iter().map(|proof| &proof.v.value).sum();
        let r_sum: BigUint = liability_proofs.iter().map(|proof| &proof.r).sum();
        let k = Field256::from(v_sum.to_bigint().unwrap() - r_sum.to_bigint().unwrap());

        let proof = SchnorrProof::create(k, h, z_solvency);
        SolvencyProof { schnorr: proof }
    }

    fn verify(&self) -> bool {
        self.schnorr.verify()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solvency_create_and_verify() {
        let g = Point::g();
        let h = point_mul(Point::g(), &Field256::from(2));

        let x = &Field256::from(1);
        let y = &point_mul(Point::g(), x);
        let bal = &Field256::from(10);
        let asset = AssetProof::create(Some(x), y, bal, &g, &h);

        let username = b"testuser";
        let balance = BigUint::from(10u8);
        let liability = LiabilityProof::create(&username[..], &balance, g, h);

        let h = point_mul(Point::g(), &Field256::from(2));
        let commitment = SolvencyProof::create(&[asset], &[liability], h);

        assert!(commitment.verify() "commitment not able to be verified");
    }
}
