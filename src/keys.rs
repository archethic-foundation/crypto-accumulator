use ark_bls12_381::{Fr, G2Projective as G2};
use ark_ec::Group;
use ark_ff::UniformRand;
use rand::thread_rng;

pub struct SecretKey {
    pub alpha: Fr,
}

pub struct PublicKey {
    pub g2: G2,
    pub alpha: G2,
}

impl SecretKey {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let alpha = Fr::rand(&mut rng);
        Self { alpha }
    }

    pub fn to_public_key(&self) -> PublicKey {
        let g2 = G2::generator();
        let alpha = g2 * self.alpha;
        
        PublicKey { g2, alpha }
    }
}