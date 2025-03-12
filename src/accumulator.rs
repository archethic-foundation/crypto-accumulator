use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::Group;

use crate::SecretKey;

/// Represents a cryptographic accumulator in the G1 group.
///
/// The accumulator maintains a single G1 group element that accumulates
/// values through the `add` operation. The accumulator starts with the
/// generator of G1 and grows with each addition.
#[derive(Clone)]
pub struct Accumulator {
    pub value: G1,
}

/// Represents an element that can be added to the accumulator.
///
/// Contains both the G1 group element representation of the value
/// and the corresponding scalar in Fr (the scalar field).
#[derive(Clone)]
pub struct Element {
    pub value: G1,
    pub x: Fr,
}

impl Accumulator {
    /// Creates a new accumulator initialized with the G1 generator.
    ///
    /// # Examples
    /// ```
    /// use crypto_accumulator::Accumulator;
    /// let accumulator = Accumulator::new();
    /// ```
    pub fn new() -> Self {
        Self {
            value: G1::generator(),
        }
    }

    /// Adds an element to the accumulator using the secret key.
    ///
    /// The addition operation combines the element's value with
    /// the current accumulator value scaled by the secret key's α.
    ///
    /// # Arguments
    /// * `sk` - The secret key containing the α scalar
    /// * `elem` - The element to add to the accumulator
    ///
    /// # Examples
    /// ```
    /// use crypto_accumulator::{Accumulator, SecretKey, Element};
    /// use ark_bls12_381::{Fr, G1Projective};
    /// use ark_ec::Group;
    /// 
    /// let mut accumulator = Accumulator::new();
    /// let sk = SecretKey::new();
    /// let elem = Element {
    ///     value: G1Projective::generator(),
    ///     x: Fr::from(42),
    /// };
    /// accumulator.add(&sk, &elem);
    /// ```
    ///
    /// # Security
    /// The operation requires the secret key to maintain the
    /// cryptographic properties of the accumulator.
    pub fn add(&mut self, sk: &SecretKey, elem: &Element) {
        let alpha_point = self.value * sk.alpha;
        self.value = elem.value + alpha_point;
    }
}