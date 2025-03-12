use ark_bls12_381::{Fr, G2Projective as G2};
use ark_ec::Group;
use ark_ff::UniformRand;
use rand::thread_rng;

pub struct SecretKey {
    /// Scalar value in Fr (BLS12-381's scalar field)
    /// 
    /// Fr is the scalar field of G1, but note that both G1 and G2 groups share
    /// the same order (r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001)
    /// which is the modulus of this field. This scalar is used for exponentiation
    /// in both G1 and G2 groups.
    pub alpha: Fr,
}

/// Represents the public key in the BLS12-381 cryptographic scheme.
///
/// The public key consists of two elements in the G2 group:
/// - g2: The generator of the G2 group
/// - alpha: The generator multiplied by the secret scalar (g2 * α)
///
/// # Security
/// The public key can be safely shared as it does not reveal information
/// about the secret scalar due to the hardness of the discrete logarithm problem.
pub struct PublicKey {
    pub g2: G2,
    pub alpha: G2,
}

impl SecretKey {
  
    /// Generates a new SecretKey with a cryptographically secure random α scalar.
    ///
    /// # Examples
    /// ```
    /// use crypto_accumulator::SecretKey;
    /// let sk = SecretKey::new();
    /// ```
    ///
    /// # Security
    /// Uses `thread_rng` from the rand crate which is considered cryptographically secure.
    /// The randomness is crucial for security - improper initialization could compromise
    /// the entire cryptographic scheme.
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let alpha = Fr::rand(&mut rng);
        Self { alpha }
    }

    /// Converts the SecretKey to a PublicKey by performing scalar multiplication.
    ///
    /// The public key consists of two G2 elements:
    /// - g2: The generator of the G2 group
    /// - alpha: The generator multiplied by the secret scalar (g2 * α)
    ///
    /// # Examples
    /// ```
    /// use crypto_accumulator::SecretKey;
    /// let sk = SecretKey::new();
    /// let pk = sk.to_public_key();
    /// ```
    ///
    /// # Security
    /// The conversion is deterministic and safe as it only involves public
    /// group operations. The secret scalar α remains protected by the
    /// discrete logarithm problem.
    pub fn to_public_key(&self) -> PublicKey {
        let g2 = G2::generator();
        let alpha = g2 * self.alpha;
        
        PublicKey { g2, alpha }
    }
}