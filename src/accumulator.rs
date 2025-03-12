use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::{Group};

use crate::SecretKey;

#[derive(Clone)]
pub struct Accumulator {
    pub value: G1,
}

#[derive(Clone)]
pub struct Element {
    pub value: G1,
    pub x: Fr,
}

impl Accumulator {
    pub fn new() -> Self {
        Self {
            value: G1::generator(),
        }
    }

    pub fn add(&mut self, sk: &SecretKey, elem: &Element) {
        let alpha_point = self.value * sk.alpha;
        self.value = elem.value + alpha_point;
    }
}