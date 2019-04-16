use crate::fields::Field256;
use crate::proofs::compute_challenge;
use crate::secp256k1::{point_add, point_mul, Point};
use crate::serialization::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
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
        let t = point_mul(g.clone(), &r);

        // s = r + cx
        let c = compute_challenge(&[&g, &y, &t]);
        let s = r + (c * x);

        SchnorrProof { s, g, y, t }
    }

    /// Verify if the commitment is valid or not
    pub fn verify(&self) -> bool {
        // g^s
        let lhs = point_mul(self.g.clone(), &self.s);

        // t * y^c
        let rhs = point_add(
            self.t.clone(),
            &point_mul(
                self.y.clone(),
                &compute_challenge(&[&self.g, &self.y, &self.t]),
            ),
        );

        // g^s == t * y^c
        lhs == rhs
    }
}

impl Serialize for SchnorrProof {
    /// Encodes into 32 + 33 + 33 + 33 = 131 bytes
    fn serialize(&self) -> Vec<u8> {
        let mut out = vec![];
        out.extend(self.s.serialize());
        out.extend(self.g.serialize());
        out.extend(self.y.serialize());
        out.extend(self.t.serialize());
        out
    }
}

impl Deserialize for SchnorrProof {
    fn deserialize(bytes: &[u8]) -> SchnorrProof {
        let s = Field256::deserialize(&bytes[0..32]);
        let g = Point::deserialize(&bytes[32..65]);
        let y = Point::deserialize(&bytes[65..98]);
        let t = Point::deserialize(&bytes[98..]);
        SchnorrProof { s, g, y, t }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn schnorr_create_and_verify() {
        let x = Field256::from(123);
        let g = Point::g();
        let y = point_mul(Point::g(), &x);

        let proof = SchnorrProof::create(x, g, y);

        assert!(proof.verify(), "unable to verify proof")
    }

    #[test]
    fn schnorr_serialization() {
        let x = Field256::from(123);
        let g = Point::g();
        let y = point_mul(Point::g(), &x);

        let proof = SchnorrProof::create(x, g, y);
        let proof2 = SchnorrProof::deserialize(&proof.serialize());

        assert_eq!(proof, proof2)
    }
}
