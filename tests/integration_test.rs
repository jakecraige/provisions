use num_bigint::BigUint;
use provisions::fields::Field256;
use provisions::proofs::{AssetProof, LiabilityProof, SolvencyProof};
use provisions::secp256k1::{point_mul, Point};

#[test]
fn it_can_produce_valid_proof_of_solvency() {
    let g = provisions::g();
    let h = provisions::h();

    let x = Field256::from(1);
    let y = &point_mul(Point::g(), x);
    let bal = BigUint::from(10u8);
    let asset = AssetProof::create(Some(x), y, bal, &g, &h);

    let username = b"testuser";
    let balance = BigUint::from(10u8);
    let liability = LiabilityProof::create(&username[..], &balance, g, h);

    let h = provisions::h();
    let commitment = SolvencyProof::create(&[asset], &[liability], h);

    assert!(commitment.verify() "commitment not able to be verified");
}

#[test]
fn it_can_produce_invalid_proof_of_solvency() {
    let g = provisions::g();
    let h = provisions::h();

    let x = Field256::from(1);
    let y = &point_mul(Point::g(), x);
    let bal = BigUint::from(10u8);
    let asset = AssetProof::create(Some(x), y, bal, &g, &h);

    let username = b"testuser";
    let balance = BigUint::from(5u8);
    let liability = LiabilityProof::create(&username[..], &balance, g, h);

    let h = provisions::h();
    let commitment = SolvencyProof::create(&[asset], &[liability], h);

    assert!(!commitment.verify() "commitment verified");
}
