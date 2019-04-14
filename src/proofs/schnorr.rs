use crate::fields::Field256;
use crate::proofs::compute_challenge;
use crate::secp256k1::Point;

pub struct SchnorrProof {
    s: Field256,
    g: Point,
    y: Point,
    t: Point,
}

impl SchnorrProof {
    /// Create commitment to x such that y = g^x
    pub fn create(x: Field256, g: Point, y: Point) -> SchnorrProof {
        // t = g^r
        let r = Field256::rand();
        let mut t = g.clone();
        t.mul(&r);

        // s = r + cx
        let c = compute_challenge(&[&g, &y, &t]);
        let s = r + (c * x);

        SchnorrProof { s, g, y, t }
    }

    /// Verify if the commitment is valid or not
    pub fn verify(&self) -> bool {
        // g^s
        let mut lhs = self.g.clone();
        lhs.mul(&self.s);

        // t * y^c
        let mut y = self.y.clone();
        y.mul(&compute_challenge(&[&self.g, &self.y, &self.t]));
        let mut rhs = self.t.clone();
        rhs.add(&y);

        // g^s == t * y^c
        lhs == rhs
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn schnorr_create_and_verify() {
        let x = Field256::from(123);
        let g = Point::g();
        let mut y = Point::g();
        y.mul(&x);

        let proof = SchnorrProof::create(x, g, y);

        assert!(proof.verify(), "unable to verify proof")
    }
}
