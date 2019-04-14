use crate::fields::Field256;
use crate::proofs::compute_challenge;
use crate::secp256k1::{pedersen_commitment, point_add, point_inverse, point_mul, Point};

/// Commitment to x given: (g, h, l = g^x*h^y).
///
/// Interactive protocol for verifying a pedersen commitment (g, h, l = g^x*h^y) where x is 0 or 1;
///
/// 1) Prover selects u0, u1, cf randomly from Z_q and produces:
///     a0 = h^u0 * g^(-x*cf),
///     a1 = h^u1 * g^((1-x)*cf)
///
/// 2) Verify sends challenge c from Z_q and
///
/// 3) Prover computes:
///     c1 = x * (c - cf) + (1 - x) * cf
///     r0 = u0 + (c - c1) * y
///     r1 = u1 + c1 * y
///     Sends (c1, r0, r1) to verifier
///
/// 4) Verifier accepts if:
///     h^r0 = a0(l)^(c-c1)
///     h^r1 = a1(lg^-1)^c1
///
/// Our implementation uses the Fiat-Shamir heuristic to make the protocol non-interactive.
pub struct BinaryProof {
    g: Point,
    h: Point,
    pub l: Point,
    a0: Point,
    a1: Point,
    c1: Field256,
    r0: Field256,
    r1: Field256,
}

impl BinaryProof {
    /// Create a non-interactive binary commitment to x with the pedersen commitment g^x*h^y
    pub fn create(x: &Field256, y: &Field256, g: &Point, h: &Point) -> BinaryProof {
        if !x.is_binary() {
            panic!("Only comitting to 0 or 1 is supported. Was: {}", x);
        }

        // l = g^x*h^y
        let l = pedersen_commitment(g.clone(), x, h.clone(), y);

        let (u0, u1, cf) = (Field256::rand(), Field256::rand(), Field256::rand());

        // a0 = h^u0 * g^(-x*cf),
        let a0 = pedersen_commitment(h.clone(), &u0, g.clone(), &-(x * &cf));
        // a1 = h^u1 * g^((1-x)*cf)
        let a1 = pedersen_commitment(h.clone(), &u1, g.clone(), &((Field256::one() - x) * &cf));

        let c = compute_challenge(&[&g, &h, &l, &a0, &a1]);
        let c1 = x * (&c - &cf) + (Field256::one() - x) * &cf;
        let r0 = u0 + (&c - &c1) * y;
        let r1 = u1 + &c1 * y;

        BinaryProof {
            g: g.clone(),
            h: h.clone(),
            l,
            a0,
            a1,
            c1,
            r0,
            r1,
        }
    }

    /// Verify if the proof is valid or not
    pub fn verify(&self) -> bool {
        let c = compute_challenge(&[&self.g, &self.h, &self.l, &self.a0, &self.a1]);

        // h^r0 = a0(l)^(c-c1)
        let p1_lhs = point_mul(self.h.clone(), &self.r0);
        let p1_rhs = point_add(
            self.a0.clone(),
            &point_mul(self.l.clone(), &(&c - &self.c1)),
        );
        let p1 = p1_lhs == p1_rhs;

        // h^r1 = a1(lg^-1)^c1
        let p2_lhs = point_mul(self.h.clone(), &self.r1);
        let p2_rhs = point_add(
            self.a1.clone(),
            &point_mul(
                point_add(self.l.clone(), &point_inverse(self.g.clone())),
                &self.c1,
            ),
        );
        let p2 = p2_lhs == p2_rhs;

        return p1 && p2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_commit_to_true() {
        let g = crate::g();
        let h = crate::h();
        let y = &Field256::rand();

        let x = &Field256::from(1);
        let commitment = BinaryProof::create(x, y, &g, &h);

        assert!(commitment.verify() "commitment not able to be verified");
    }

    #[test]
    fn verify_commit_to_false() {
        let g = crate::g();
        let h = crate::h();
        let y = &Field256::rand();

        let x = &Field256::from(0);
        let commitment = BinaryProof::create(x, y, &g, &h);

        assert!(commitment.verify() "commitment not able to be verified");
    }

    #[test]
    #[should_panic]
    fn verify_x_is_validated() {
        let g = crate::g();
        let h = crate::h();
        let y = &Field256::rand();

        let x = &Field256::from(25);
        BinaryProof::create(x, y, &g, &h);
    }
}
