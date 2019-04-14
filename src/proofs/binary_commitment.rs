use crate::fields::Field256;
use crate::proofs::compute_challenge;
use crate::secp256k1::Point;

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
pub struct BinaryCommitment {
    g: Point,
    h: Point,
    pub l: Point,
    a0: Point,
    a1: Point,
    c1: Field256,
    r0: Field256,
    r1: Field256,
}

impl BinaryCommitment {
    /// Create a non-interactive binary commitment to x with the pedersen commitment g^x*h^y
    pub fn create(x: &Field256, y: &Field256, g: &Point, h: &Point) -> BinaryCommitment {
        if !x.is_binary() {
            panic!("Only comitting to 0 or 1 is supported. Was: {}", x);
        }

        // l = g^x*h^y
        let mut gx = g.clone();
        gx.mul(x);
        let mut hy = h.clone();
        hy.mul(y);
        let mut l = gx;
        l.add(&hy);

        let (u0, u1, cf) = (Field256::rand(), Field256::rand(), Field256::rand());

        // a0 = h^u0 * g^(-x*cf),
        let mut hu0 = h.clone();
        hu0.mul(&u0);
        let mut gxcf = g.clone();
        gxcf.mul(&-(x * &cf));
        let mut a0 = hu0;
        a0.add(&gxcf);

        // a1 = h^u1 * g^((1-x)*cf)
        let mut hu1 = h.clone();
        hu1.mul(&u1);
        let mut gxcf = g.clone();
        gxcf.mul(&((Field256::one() - x) * &cf));
        let mut a1 = hu1;
        a1.add(&gxcf);

        let c = compute_challenge(&[&g, &h, &l, &a0, &a1]);
        let c1 = x * (&c - &cf) + (Field256::one() - x) * &cf;
        let r0 = u0 + (&c - &c1) * y;
        let r1 = u1 + &c1 * y;

        BinaryCommitment {
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
        let mut hr0 = self.h.clone();
        hr0.mul(&self.r0);
        let mut a0l = self.a0.clone();
        let mut lc = self.l.clone();
        lc.mul(&(&c - &self.c1));
        a0l.add(&lc);
        let p1 = hr0 == a0l;

        // h^r1 = a1(lg^-1)^c1
        let mut hr1 = self.h.clone();
        hr1.mul(&self.r1);
        let mut a1lg = self.a1.clone();
        let mut lg = self.g.clone();
        lg.mul(&Field256::from(-1i8));
        lg.add(&self.l);
        lg.mul(&self.c1);
        a1lg.add(&lg);
        let p2 = hr1 == a1lg;

        return p1 && p2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_commit_to_true() {
        let g = Point::g();
        let mut h = Point::g();
        h.mul(&Field256::from(2));
        let y = &Field256::rand();

        let x = &Field256::from(1);
        let commitment = BinaryCommitment::create(x, y, &g, &h);

        assert!(commitment.verify() "commitment not able to be verified");
    }

    #[test]
    fn verify_commit_to_false() {
        let g = Point::g();
        let mut h = Point::g();
        h.mul(&Field256::from(2));
        let y = &Field256::rand();

        let x = &Field256::from(0);
        let commitment = BinaryCommitment::create(x, y, &g, &h);

        assert!(commitment.verify() "commitment not able to be verified");
    }

    #[test]
    #[should_panic]
    fn verify_x_is_validated() {
        let g = Point::g();
        let mut h = Point::g();
        h.mul(&Field256::from(2));
        let y = &Field256::rand();

        let x = &Field256::from(25);
        BinaryCommitment::create(x, y, &g, &h);
    }
}
