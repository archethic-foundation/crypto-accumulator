use ark_bls12_381::{Fr, G1Projective as G1, Bls12_381};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{UniformRand, Field};  // Add Field and PrimeField traits
use rand::thread_rng;

use crate::{Accumulator, Element, SecretKey, PublicKey};

pub struct MembershipWitness {
    pub value: G1,
}

pub struct NonMembershipWitness {
    pub d: G1,
    pub v: Fr,
}

impl MembershipWitness {
    pub fn generate(acc: &Accumulator, sk: &SecretKey, elem: &Element) -> Self {
        // Witness computation: w = acc^(1/(x + α))
        // where x is the element value and α is the secret key
        
        // Calculate (x + α)
        let sum = elem.x + sk.alpha;
        
        // Calculate modular multiplicative inverse
        let inv = sum.inverse().expect("Failed to compute inverse");
        
        // Compute witness
        let witness = acc.value * inv;
        
        Self { value: witness }
    }

    pub fn verify(&self, acc: &Accumulator, elem: &Element, pk: &PublicKey) -> bool {
        // e(w, g2^α) * e(g1^x, g2) = e(acc, g2)
        // where w is the witness, x is the element, acc is the accumulator value
        
        // Calculate left-hand side: e(w, g2^α) * e(g1^x, g2)
        let pairing1 = Bls12_381::pairing(self.value, pk.alpha);
        let pairing2 = Bls12_381::pairing(elem.value, pk.g2);
        
        // In arkworks, we combine pairings with addition in the target group
        let lhs = pairing1 + pairing2;
        
        // Calculate right-hand side: e(acc, g2)
        let rhs = Bls12_381::pairing(acc.value, pk.g2);
        
        // Compare the pairing results
        lhs == rhs
    }
}

impl NonMembershipWitness {
    pub fn generate(acc: &Accumulator, sk: &SecretKey, elem: &Element) -> Self {
        // For an element y that is not in the accumulator,
        // we need to find (d, v) such that acc = g^v * d^(y + α)
        
        // Calculate (y + α)
        let sum = elem.x + sk.alpha;
        
        // Generate random value for v
        let mut rng = thread_rng();
        let v = Fr::rand(&mut rng);
        
        // Calculate g^v
        let g_v = G1::generator() * v;
        
        // Calculate acc * (g^v)^(-1)
        let g_v_inv = -g_v;
        let temp = acc.value + g_v_inv;
        
        // Calculate d = (acc/g^v)^(1/(y + α))
        let sum_inv = sum.inverse().expect("Failed to compute inverse");
        let d = temp * sum_inv;
        
        // Verify: acc = g^v * d^(y + α)
        let d_pow_sum = d * sum;
        let result = g_v + d_pow_sum;
        
        assert!(result == acc.value, "Invalid witness generated");
        
        Self { d, v }
    }

    pub fn verify(&self, acc: &Accumulator, elem: &Element, pk: &PublicKey) -> bool {
        // For a valid non-membership witness (d, v), we verify:
        // e(acc, g2) = e(g1^v, g2) * e(d, g2^α * g2^y)
        // where y is the element we're proving non-membership for

        // Calculate g2^y
        let g2_y = pk.g2 * elem.x;

        // Calculate g2^α * g2^y
        let alpha_plus_y = pk.alpha + g2_y;

        // Calculate left-hand side: e(acc, g2)
        let lhs = Bls12_381::pairing(acc.value, pk.g2);

        // Calculate right-hand side: e(g1^v, g2) * e(d, g2^α * g2^y)
        let g1_v = G1::generator() * self.v;
        let pairing1 = Bls12_381::pairing(g1_v, pk.g2);
        let pairing2 = Bls12_381::pairing(self.d, alpha_plus_y);
        
        // In arkworks, we combine pairings with addition in the target group
        let rhs = pairing1 + pairing2;

        // Compare the pairing results
        lhs == rhs
    }
}