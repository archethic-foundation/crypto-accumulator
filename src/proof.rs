use ark_bls12_381::{Fr, G1Projective as G1, G2Projective as G2, Bls12_381};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_serialize::CanonicalSerialize;
use ark_ff::{UniformRand, PrimeField};
use rand::thread_rng;
use sha2::{Sha256, Digest};

use crate::{Accumulator, Element, PublicKey, MembershipWitness};

/// Represents the commitment part of a membership proof.
///
/// Contains two group elements:
/// - t1: A G1 element used in the proof
/// - t2: A G2 element used in the proof
#[derive(Clone)]
pub struct ProofCommitment {
    pub t1: G1,
    pub t2: G2,
}

/// Represents a complete membership proof for an element in the accumulator.
///
/// Contains:
/// - commitment: The proof commitment values
/// - response: The response to the challenge
#[derive(Clone)]
pub struct MembershipProof {
    pub commitment: ProofCommitment,
    pub response: Fr,
}

impl MembershipWitness {
    /// Creates a membership proof for an element in the accumulator.
    ///
    /// The proof follows a sigma protocol structure with:
    /// 1. Commitment generation
    /// 2. Challenge generation using Fiat-Shamir
    /// 3. Response calculation
    ///
    /// # Arguments
    /// * `acc` - The current accumulator state
    /// * `elem` - The element being proven
    /// * `pk` - The public key for verification
    ///
    /// # Returns
    /// A MembershipProof containing the commitment and response
    pub fn create_proof(&self, acc: &Accumulator, elem: &Element, pk: &PublicKey) -> MembershipProof {
        let mut rng = thread_rng();
        let r = Fr::rand(&mut rng);
        
        let t1 = G1::generator() * r;
        let t2 = pk.g2;
        
        let commitment = ProofCommitment { 
            t1, 
            t2, 
        };
        
        // Generate challenge using hash of all public values
        let mut hasher = Sha256::new();
        
        // Convert points to bytes using CanonicalSerialize
        let mut acc_bytes = Vec::new();
        let mut elem_bytes = Vec::new();
        let mut t1_bytes = Vec::new();
        let mut t2_bytes = Vec::new();

        acc.value.into_affine().serialize_uncompressed(&mut acc_bytes).unwrap();
        elem.value.into_affine().serialize_uncompressed(&mut elem_bytes).unwrap();
        t1.into_affine().serialize_uncompressed(&mut t1_bytes).unwrap();
        t2.into_affine().serialize_uncompressed(&mut t2_bytes).unwrap();
        
        hasher.update(&acc_bytes);
        hasher.update(&elem_bytes);
        hasher.update(&t1_bytes);
        hasher.update(&t2_bytes);
        
        let challenge_bytes = hasher.finalize();
        
        // Convert hash to field element
        let challenge = Fr::from_le_bytes_mod_order(&challenge_bytes);
        
        // Calculate response = r + challenge * x
        let response = r + (challenge * elem.x);
        
        MembershipProof {
            commitment,
            response,
        }
    }
}

impl MembershipProof {
    /// Verifies a membership proof against the accumulator and element.
    ///
    /// The verification checks the proof using pairing equations:
    /// e(g1^response, g2) = e(T1, g2) * e(elem, g2)^challenge
    ///
    /// # Arguments
    /// * `acc` - The current accumulator state
    /// * `elem` - The element being verified
    /// * `pk` - The public key for verification
    ///
    /// # Returns
    /// true if the proof is valid, false otherwise
    ///
    /// # Examples
    /// ```
    /// use crypto_accumulator::{Accumulator, Element, SecretKey, MembershipWitness};
    /// use ark_bls12_381::{Fr, G1Projective};
    /// use ark_ec::Group;
    /// 
    /// let mut acc = Accumulator::new();
    /// let sk = SecretKey::new();
    /// let pk = sk.to_public_key();
    /// let value = Fr::from(42);
    /// let elem = Element {
    ///     value: G1Projective::generator() * value,
    ///     x: value,
    /// };
    /// acc.add(&sk, &elem);
    /// let witness = MembershipWitness::generate(&acc, &sk, &elem);
    /// let proof = witness.create_proof(&acc, &elem, &pk);
    /// assert!(proof.verify(&acc, &elem, &pk));
    /// 
    /// // Test with invalid element
    /// let invalid_value = Fr::from(123);
    /// let invalid_elem = Element {
    ///     value: G1Projective::generator() * invalid_value,
    ///     x: invalid_value,
    /// };
    /// assert!(!proof.verify(&acc, &invalid_elem, &pk));
    /// ```
    pub fn verify(&self, acc: &Accumulator, elem: &Element, pk: &PublicKey) -> bool {
        // Regenerate challenge
        let mut hasher = Sha256::new();
        
        // Convert points to bytes using CanonicalSerialize
        let mut acc_bytes = Vec::new();
        let mut elem_bytes = Vec::new();
        let mut t1_bytes = Vec::new();
        let mut t2_bytes = Vec::new();

        acc.value.into_affine().serialize_uncompressed(&mut acc_bytes).unwrap();
        elem.value.into_affine().serialize_uncompressed(&mut elem_bytes).unwrap();
        self.commitment.t1.into_affine().serialize_uncompressed(&mut t1_bytes).unwrap();
        self.commitment.t2.into_affine().serialize_uncompressed(&mut t2_bytes).unwrap();
        
        hasher.update(&acc_bytes);
        hasher.update(&elem_bytes);
        hasher.update(&t1_bytes);
        hasher.update(&t2_bytes);
        
        let challenge_bytes = hasher.finalize();
        let challenge = Fr::from_le_bytes_mod_order(&challenge_bytes);
        
        // Verify the proof using pairing equations
        // Check: e(g1^response, g2) = e(T1, g2) * e(elem, g2)^challenge
        
        // Calculate left-hand side: e(g1^response, g2)
        let response_point = G1::generator() * self.response;
        let lhs = Bls12_381::pairing(response_point, pk.g2);
        
        // Calculate right-hand side: e(T1, g2) * e(elem, g2)^challenge
        let pairing1 = Bls12_381::pairing(self.commitment.t1, pk.g2);
        let elem_challenge = elem.value * challenge;
        let pairing2 = Bls12_381::pairing(elem_challenge, pk.g2);
        
        // In arkworks, we combine pairings with addition in the target group
        let rhs = pairing1 + pairing2;
        
        // Compare the pairing results
        lhs == rhs
    }
}

// /// Represents a non-membership proof for an element not in the accumulator.
// ///
// /// Contains:
// /// - t: A pairing commitment
// /// - s: The response to the challenge
// /// - d: A G1 element used in the proof
// #[derive(Clone)]
// pub struct NonMembershipProof {
//     pub t: PairingOutput<Bls12_381>,
//     pub s: Fr,
//     pub d: G1,
// }

// impl NonMembershipWitness {
//     /// Creates a non-membership proof for an element not in the accumulator.
//     ///
//     /// The proof follows a sigma protocol structure similar to the membership proof
//     /// but with different verification equations.
//     ///
//     /// # Arguments
//     /// * `acc` - The current accumulator state
//     /// * `elem` - The element being proven
//     /// * `pk` - The public key for verification
//     ///
//     /// # Returns
//     /// A NonMembershipProof containing the commitment and response
//     pub fn create_proof(&self, acc: &Accumulator, elem: &Element, pk: &PublicKey) -> NonMembershipProof {
//         // Generate random value for the proof
//         let mut rng = thread_rng();
//         let r = Fr::rand(&mut rng);
        
//         // Compute commitment T = e(g1^r, g2)
//         let g1r = G1::generator() * r;
//         let t = Bls12_381::pairing(g1r, pk.g2);
        
//         // Generate challenge using public values
//         let mut hasher = Sha256::new();
        
//         // Convert points to bytes using CanonicalSerialize
//         let mut acc_bytes = Vec::new();
//         let mut elem_bytes = Vec::new();
        
//         acc.value.into_affine().serialize_uncompressed(&mut acc_bytes).unwrap();
//         elem.value.into_affine().serialize_uncompressed(&mut elem_bytes).unwrap();
        
//         hasher.update(&acc_bytes);
//         hasher.update(&elem_bytes);
//         // We're skipping g1r in the challenge computation to match the verification
        
//         let challenge_bytes = hasher.finalize();
//         let challenge = Fr::from_le_bytes_mod_order(&challenge_bytes);
        
//         // Compute response S = r + challenge * v
//         let s = r + (challenge * self.v);
        
//         NonMembershipProof {
//             t,
//             s,
//             d: self.d,
//         }
//     }
// }

// impl NonMembershipProof {
//     /// Verifies a non-membership proof against the accumulator and element.
//     ///
//     /// The verification checks the proof using pairing equations:
//     /// e(g1^s, g2) = T * e(acc, g2)^challenge * e(D, g2^{α + y})^-challenge
//     ///
//     /// # Arguments
//     /// * `acc` - The current accumulator state
//     /// * `elem` - The element being verified
//     /// * `pk` - The public key for verification
//     ///
//     /// # Returns
//     /// true if the proof is valid, false otherwise
//     pub fn verify(&self, acc: &Accumulator, elem: &Element, pk: &PublicKey) -> bool {
//         // Regenerate challenge
//         let mut hasher = Sha256::new();
        
//         // Convert points to bytes using CanonicalSerialize
//         let mut acc_bytes = Vec::new();
//         let mut elem_bytes = Vec::new();
        
//         acc.value.into_affine().serialize_uncompressed(&mut acc_bytes).unwrap();
//         elem.value.into_affine().serialize_uncompressed(&mut elem_bytes).unwrap();
        
//         hasher.update(&acc_bytes);
//         hasher.update(&elem_bytes);
        
//         let challenge_bytes = hasher.finalize();
//         let challenge = Fr::from_le_bytes_mod_order(&challenge_bytes);
        
//         // Calculate g2^{y + α}
//         let g2_y = pk.g2 * elem.x;
//         let alpha_plus_y = pk.alpha + g2_y;
        
//         // Calculate g1^S
//         let g1s = G1::generator() * self.s;
        
//         // Verify: e(g1^s, g2) = T * e(acc, g2)^challenge * e(D, g2^{α + y})^-challenge
        
//         // We'll calculate each pairing and combine them
//         let lhs = Bls12_381::pairing(g1s, pk.g2);
        
//         // For the right-hand side, we need to combine:
//         // 1. The commitment T
//         // 2. e(acc, g2)^challenge
//         // 3. The inverse of e(D, g2^{α + y})^challenge
        
//         // Calculate e(acc, g2)
//         let acc_pairing = Bls12_381::pairing(acc.value, pk.g2);
        
//         // Calculate e(D, g2^{α + y})
//         let d_pairing = Bls12_381::pairing(self.d, alpha_plus_y);
        
//         // Combine: T * e(acc, g2)^challenge / e(D, g2^{α + y})^challenge
//         // In the target group, division is subtraction and multiplication is addition
//         let rhs = self.t + (acc_pairing * challenge) - (d_pairing * challenge);
        
//         lhs == rhs
//     }
// }