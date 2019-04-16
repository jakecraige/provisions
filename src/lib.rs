#![allow(dead_code)]
#![allow(unused_variables)]

use crate::secp256k1::Point;

#[macro_use]
extern crate lazy_static;

mod bigint;
pub mod fields;
pub mod proofs;
pub mod secp256k1;
pub mod serialization;
mod util;

lazy_static! {
    static ref h_point: Point = Point::from_hash(b"PROVISIONS").unwrap();
}

pub fn g() -> Point {
    Point::g()
}

pub fn h() -> Point {
    h_point.clone()
}
