use crate::fields::Field256;
use crate::proofs::binary_commitment::BinaryCommitment;
use crate::proofs::compute_challenge;
use crate::secp256k1::{pedersen_commitment, point_mul, point_mul_add, Point};

pub struct AssetCommitment {
    g: Point,
    h: Point,
    y: Point,
    b: Point,
    l: Point,
    a1: Point,
    a2: Point,
    a3: Point,

    rs: Field256,
    rv: Field256,
    rt: Field256,
    rxhat: Field256,

    /// for solvency verification, secret value and only known to E
    v: Field256,

    /// balance_comm.l is == p
    balance_comm: BinaryCommitment,
}

impl AssetCommitment {
    pub fn create(
        x: Option<&Field256>,
        y: &Point,
        bal: &Field256,
        g: &Point,
        h: &Point,
    ) -> AssetCommitment {
        let b = point_mul(g.clone(), bal);
        let s = if x.is_some() {
            Field256::one()
        } else {
            Field256::zero()
        };
        let zero = Field256::zero();
        let xhat = x.unwrap_or(&zero);

        // Commitment to balance
        let v = Field256::rand();
        let balance_comm = BinaryCommitment::create(&s, &v, &b, &h);

        // Commitment to private key knowledge
        let t = Field256::rand();
        let l = pedersen_commitment(y.clone(), &s, h.clone(), &t);

        let (u1, u2, u3, u4) = (
            Field256::rand(),
            Field256::rand(),
            Field256::rand(),
            Field256::rand(),
        );
        let a1 = pedersen_commitment(b.clone(), &u1, h.clone(), &u2);
        let a2 = pedersen_commitment(y.clone(), &u1, h.clone(), &u3);
        let a3 = pedersen_commitment(g.clone(), &u4, h.clone(), &u3);

        let c = &compute_challenge(&[&y, &g, &h, &b, &balance_comm.l, &l, &a1, &a2, &a3]);
        let rs = &u1 + c * &s;
        let rv = &u2 + c * &v;
        let rt = &u3 + c * &t;
        let rxhat = &u4 + c * xhat;

        AssetCommitment {
            g: g.clone(),
            h: h.clone(),
            y: y.clone(),
            b,
            l,
            a1,
            a2,
            a3,
            rs,
            rv,
            rt,
            rxhat,
            v,
            balance_comm,
        }
    }

    /// Verify if the proof is valid or not
    pub fn verify(&self) -> bool {
        let (g, h, y, b, p, l, a1, a2, a3, rs, rv, rt, rxhat) = (
            self.g.clone(),
            self.h.clone(),
            self.y.clone(),
            self.b.clone(),
            self.balance_comm.l.clone(),
            self.l.clone(),
            self.a1.clone(),
            self.a2.clone(),
            self.a3.clone(),
            &self.rs,
            &self.rv,
            &self.rt,
            &self.rxhat,
        );
        let c = &compute_challenge(&[&y, &g, &h, &b, &p, &l, &a1, &a2, &a3]);

        // Protocol 1: Verify honest computation of p, l and knowledge of x.
        let p1 = pedersen_commitment(b, &rs, h.clone(), &rv) == point_mul_add(p, c, &a1);
        let p2 = pedersen_commitment(y, &rs, h.clone(), &rt) == point_mul_add(l.clone(), c, &a2);
        let p3 = pedersen_commitment(g, &rxhat, h, &rt) == point_mul_add(l, c, &a3);
        let protocol_verified = p1 && p2 && p3;

        // Protocol 4: Verify binary proof of knowledge of s in [0,1] and v of p
        let balance_verified = self.balance_comm.verify();

        protocol_verified && balance_verified
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_asset_commitment_with_sk() {
        let g = Point::g();
        let h = point_mul(Point::g(), &Field256::from(175));

        let x = &Field256::from(1);
        let y = &point_mul(Point::g(), x);
        let bal = &Field256::from(123);
        let commitment = AssetCommitment::create(Some(x), y, bal, &g, &h);

        assert!(commitment.verify() "commitment not able to be verified");
    }

    #[test]
    fn verify_asset_commitment_without_sk() {
        let g = Point::g();
        let h = point_mul(Point::g(), &Field256::from(175));

        let x = &Field256::from(1);
        let y = &point_mul(Point::g(), x);
        let bal = &Field256::from(123);
        let commitment = AssetCommitment::create(None, y, bal, &g, &h);

        assert!(commitment.verify() "commitment not able to be verified");
    }
}
