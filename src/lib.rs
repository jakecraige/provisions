#![allow(dead_code)]
#![allow(unused_variables)]

use crate::secp256k1::Point;

mod bigint;
pub mod fields;
pub mod proofs;
pub mod secp256k1;
mod util;

pub fn g() -> Point {
    Point::g()
}

pub fn h() -> Point {
    Point::from_hash(b"PROVISIONS").unwrap()
}
