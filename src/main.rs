use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::Group;
use sha2::{Sha256, Digest};
use ark_ff::PrimeField;

mod accumulator;
mod keys;
mod witness;
mod proof;

use crate::accumulator::{Accumulator, Element};
use crate::keys::{SecretKey, PublicKey};
use crate::witness::{MembershipWitness, NonMembershipWitness};

fn hash_to_field(message: &[u8]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(message);
    let hash = hasher.finalize();
    
    // Convert hash to a field element by reducing modulo the field order
    // This ensures the value is within the BLS12-381 scalar field
    Fr::from_be_bytes_mod_order(&hash)
}

fn main() {
    // Setup
    let sk = SecretKey::new();
    let pk = sk.to_public_key();
    let mut acc = Accumulator::new();

    // Create and add element
    let message = b"test_element";
    let x = hash_to_field(message);
    let elem_value = G1::generator() * x;
    let elem = Element { value: elem_value, x };

    acc.add(&sk, &elem);

    // Generate and verify membership witness
    let witness = MembershipWitness::generate(&acc, &sk, &elem);
    assert!(witness.verify(&acc, &elem, &pk), "Membership verification failed");
    println!("✓ Membership witness is valid for an accumulated element");

    // Test invalid membership witness for non-accumulated element
    let non_message = b"non_member_element";
    let y = hash_to_field(non_message);
    let nonelem_value = G1::generator() * y;
    let nonelem = Element { value: nonelem_value, x: y };

    // Try to generate a witness for the non-accumulated element
    // This should technically work but verification should fail
    let witness_mem_invalid = MembershipWitness::generate(&acc, &sk, &nonelem);

    // Verify membership - this should fail
    assert!(!witness_mem_invalid.verify(&acc, &nonelem, &pk), "Membership for the non-existing element should not be valid");
    println!("✓ Membership witness is invalid for a non-accumulated element");

    // Test non-membership
    let non_message = b"non_member_element";
    let y = hash_to_field(non_message);
    let nonelem_value = G1::generator() * y;
    let nonelem = Element { value: nonelem_value, x: y };

    let non_mem_witness = NonMembershipWitness::generate(&acc, &sk, &nonelem);
    assert!(non_mem_witness.verify(&acc, &nonelem, &pk), "Non-membership verification failed");
    println!("✓ Non-membership witness is valid for a non-accumulated element");

    // This should fail for elements that are actually in the accumulator
    let is_non_member = non_mem_witness.verify(&acc, &elem, &pk);
    assert!(!is_non_member, "Non-membership verification should fail for members");
    println!("✓ Non-membership witness is invalid for an accumulated element");

    // Add the non-element to the accumulator
    acc.add(&sk, &nonelem);
    
    // Verify that the non-membership witness is no longer valid
    let is_non_member = non_mem_witness.verify(&acc, &nonelem, &pk);
    assert!(!is_non_member, "Non-membership verification should fail for element added to the accumulator");
    println!("✓ Non-membership witness is invalid after adding the element to the accumulator");

    // Generate and verify ZK proof
    let proof = witness.create_proof(&acc, &elem, &pk);
    assert!(proof.verify(&acc, &elem, &pk), "ZK proof verification failed");
    println!("✓ ZK proof verification successful");

    println!("Testing invalid proof scenarios:");

    // Test 1: Tampered element value
    let tampered_value = G1::generator() * Fr::from(43u64);
    let tampered_elem = Element {
        value: tampered_value, // Different value
        x: elem.x,             // Same x value as the valid element
    };
    let is_valid_proof = proof.verify(&acc, &tampered_elem, &pk);
    assert!(!is_valid_proof, "Proof verification should fail with tampered element");
    println!("✓ Proof correctly failed for tampered element");

    // Test 2: Tampered proof response
    use crate::proof::MembershipProof;
    let tampered_proof = MembershipProof {
        commitment: proof.clone().commitment,
        response: proof.response + Fr::from(1u64), // Tampered response
    };
    let is_valid_proof = tampered_proof.verify(&acc, &elem, &pk);
    assert!(!is_valid_proof, "Proof verification should fail with tampered response");
    println!("✓ Proof correctly failed for tampered response");

    // Test 3: Wrong element trying to use valid proof
    let wrong_x = Fr::from(99u64);
    let wrong_value = G1::generator() * wrong_x;
    let wrong_elem = Element {
        value: wrong_value,
        x: wrong_x,
    };
    let is_valid_proof = proof.verify(&acc, &wrong_elem, &pk);
    assert!(!is_valid_proof, "Proof verification should fail with wrong element");
    println!("✓ Proof correctly failed for wrong element");

    println!("All invalid membership proof tests passed successfully!");
}
