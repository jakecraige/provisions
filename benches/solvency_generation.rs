#[macro_use]
extern crate criterion;

use criterion::Criterion;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::Zero;
use provisions::fields::Field256;
use provisions::proofs::{AssetProof, LiabilityProof, SolvencyProof};
use provisions::secp256k1::{point_mul, Point};
use std::fmt;

/// Generate a list of assets to prove solvency with. Returns the total assets and list of
/// generated assets. Total is necessary for computing a good set of data for liabilities.
///
/// Currently we have half of the assets with their private key known.
fn gen_assets(num: usize) -> (BigUint, Vec<(Option<Field256>, Point, BigUint)>) {
    let mut assets = Vec::with_capacity(num);
    let mut total = BigUint::zero();

    for i in 0..num {
        let sk = Field256::rand();
        let pk = point_mul(provisions::g(), &sk);
        let bal = Field256::rand().value;

        if i % 2 == 0 {
            total += &bal;
            assets.push((Some(sk), pk, bal))
        } else {
            assets.push((None, pk, bal))
        }
    }

    (total, assets)
}

/// Generate a list of liabilities that sum up to the provided total.
fn gen_liabilities(num: usize, total: &BigUint) -> Vec<([u8; 32], BigUint)> {
    let mut liabilities = Vec::with_capacity(num);
    // Calculate how much to put on each liability, and since it's probably not going to divide
    // evenly, take the remainder so we can add it to one of the liabilities.
    let (amount_per_liability, excess) = total.div_rem(&BigUint::from(num));

    for i in 0..num {
        let identifier = Field256::rand().to_bytes_be();
        if i == 0 {
            liabilities.push((identifier, amount_per_liability.clone() + &excess))
        } else {
            liabilities.push((identifier, amount_per_liability.clone()))
        }
    }

    liabilities
}

fn build_asset_proofs(assets: &[(Option<Field256>, Point, BigUint)]) -> Vec<AssetProof> {
    let g = provisions::g();
    let h = provisions::h();

    assets
        .iter()
        .map(|asset| AssetProof::create(asset.0.clone(), &asset.1, asset.2.clone(), &g, &h))
        .collect()
}

fn build_liability_proofs(liabilities: &[([u8; 32], BigUint)]) -> Vec<LiabilityProof> {
    let g = provisions::g();
    let h = provisions::h();

    liabilities
        .iter()
        .map(|liab| LiabilityProof::create(&liab.0, &liab.1, g.clone(), h.clone()))
        .collect()
}

fn build_solvency_proof(
    assets: &[(Option<Field256>, Point, BigUint)],
    liabilities: &[([u8; 32], BigUint)],
) -> SolvencyProof {
    let asset_proofs = build_asset_proofs(assets);
    let liability_proofs = build_liability_proofs(liabilities);

    SolvencyProof::create(
        asset_proofs.as_slice(),
        liability_proofs.as_slice(),
        provisions::h(),
    )
}

struct Input {
    asset_count: usize,
    liability_count: usize,
}

impl Input {
    fn new(asset_count: usize, liability_count: usize) -> Input {
        Input {
            asset_count,
            liability_count,
        }
    }
}

impl fmt::Display for Input {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}x{}", self.asset_count, self.liability_count)
    }
}

fn bench_solvency(c: &mut Criterion) {
    c.sample_size(2);
    c.bench_function_over_inputs(
        "gen-solvency",
        |b, &input| {
            let (total, assets) = gen_assets(input.asset_count);
            let liabilities = gen_liabilities(input.liability_count, &total);
            b.iter(|| build_solvency_proof(assets.as_slice(), liabilities.as_slice()))
        },
        &[Input::new(10, 10)],
    );

    c.bench_function_over_inputs(
        "ver-solvency",
        |b, &input| {
            let (total, assets) = gen_assets(input.asset_count);
            let liabilities = gen_liabilities(input.liability_count, &total);
            let proof = build_solvency_proof(assets.as_slice(), liabilities.as_slice());
            b.iter(|| proof.verify())
        },
        &[Input::new(20, 20)],
    );

    c.bench_function_over_inputs(
        "gen-assets",
        |b, &input| {
            let (_, assets) = gen_assets(input.asset_count);
            b.iter(|| build_asset_proofs(assets.as_slice()))
        },
        &[Input::new(10, 10)],
    );

    c.bench_function_over_inputs(
        "gen-liabs",
        |b, &input| {
            let liabilities = gen_liabilities(input.liability_count, &BigUint::from(1000u16));
            b.iter(|| build_liability_proofs(liabilities.as_slice()))
        },
        &[Input::new(10, 10)],
    );
}

criterion_group!(create_solvency_proof, bench_solvency);
criterion_main!(create_solvency_proof);
