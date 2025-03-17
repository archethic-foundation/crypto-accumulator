use std::sync::Mutex;

use rsa::key::AccumulatorSecretKey;
use rand::{RngCore, rngs::OsRng};

use rsa::prelude::{Accumulator, MembershipProof, MembershipWitness};
use rustler::types::{Binary, OwnedBinary};
use rustler::{Encoder, Env, ResourceArc, Term};


mod atoms {
    rustler::atoms! {
        ok,
        error
    }
}

#[rustler::nif]
pub fn generate_key<'a>(env: Env<'a>) -> Term<'a> {
  let sk = AccumulatorSecretKey::new();
  let sk_bytes = sk.to_bytes();
  let sk_slice = sk_bytes.as_slice();
  let mut bin = OwnedBinary::new(sk_slice.len()).unwrap();
  bin.as_mut_slice().copy_from_slice(&sk_slice);
  (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
}
struct AccumulatorResource {
  pub inner: Mutex<Accumulator>,
}

#[rustler::resource_impl()]
impl rustler::Resource for AccumulatorResource {}

#[rustler::nif]
pub fn new_accumulator<'a>(env: Env<'a>, secret_key_bytes: Binary) -> Term<'a> {
  match AccumulatorSecretKey::try_from(secret_key_bytes.as_slice()) {
    Ok(sk) => {
      let resource = ResourceArc::new(AccumulatorResource{
        inner: Mutex::new(Accumulator::new(&sk)),
      });
      (atoms::ok(), resource).encode(env)
    },
    Err(e) => (atoms::error(), e.to_string()).encode(env),
  }
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn export_accumulator<'a>(env: Env<'a>, resource: ResourceArc<AccumulatorResource>) -> Term<'a> {
  let acc = resource.inner.lock().map_err(|e| {
      rustler::Error::Term(Box::new(format!(
          "Could not unlock instance resource as the mutex was poisoned: {e}"
      )))
  }).unwrap();
  let acc_bytes: Vec<u8> = acc.to_bytes();
  let acc_slice = acc_bytes.as_slice();

  let mut bin = OwnedBinary::new(acc_slice.len()).unwrap();
  bin.as_mut_slice().copy_from_slice(&acc_slice);
  (atoms::ok(), Binary::from_owned(bin, env)).encode(env)
}

#[rustler::nif(schedule = "DirtyCpu")]
pub fn add_element<'a>(env: Env<'a>, resource: ResourceArc<AccumulatorResource>, message: Binary) -> Term<'a> {
  let mut acc = resource.inner.lock().map_err(|e| {
      rustler::Error::Term(Box::new(format!(
          "Could not unlock instance resource as the mutex was poisoned: {e}"
      )))
  }).unwrap();

  match acc.insert_assign(message.as_slice()) {
    Ok(_) => {
      (atoms::ok()).encode(env)
    },
    Err(e) => (atoms::error(), "Failed to add element in the accumulator - {}", e.to_string()).encode(env),
  }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn get_membership_proof<'a>(env: Env<'a>, resource: ResourceArc<AccumulatorResource>, message: Binary) -> Term<'a> {
  let acc = resource.inner.lock().map_err(|e| {
      rustler::Error::Term(Box::new(format!(
          "Could not unlock instance resource as the mutex was poisoned: {e}"
      )))
  }).unwrap();

  // Generate a random 16-byte nonce
  let mut nonce = [0u8; 16];
  OsRng.fill_bytes(&mut nonce);
  
  match MembershipWitness::new(&acc, message.as_slice()) {
    Ok(witness) => {
      let proof = MembershipProof::new(&witness, &acc, &nonce);

      let proof_bytes: Vec<u8> = proof.to_bytes();
      let proof_slice = proof_bytes.as_slice();
      let mut bin = OwnedBinary::new(proof_slice.len()).unwrap();
      bin.as_mut_slice().copy_from_slice(&proof_slice);
      let mut nonce_bin = OwnedBinary::new(nonce.len()).unwrap();
      nonce_bin.as_mut_slice().copy_from_slice(&nonce);
      (atoms::ok(), Binary::from_owned(bin, env), Binary::from_owned(nonce_bin, env)).encode(env)
    },
    Err(e) => (atoms::error(), e.to_string()).encode(env)
  }
}

#[rustler::nif(schedule = "DirtyCpu")]
fn verify_membership_proof<'a>(env: Env<'a>, acc_bytes: Binary, proof_bytes: Binary, nonce: Binary) -> Term<'a> {
  let acc = match Accumulator::try_from(acc_bytes.as_slice()) {
    Ok(acc) => acc,
    Err(_) => return (atoms::error(), "Failed to deserialize the accumulator").encode(env)
  };

  let proof = match MembershipProof::try_from(proof_bytes.as_slice()) {
    Ok(proof) => proof,
    Err(_) => return (atoms::error(), "Failed to deserialize the proof").encode(env)
  };

  let is_valid = proof.verify(&acc, nonce.as_slice());
  (atoms::ok(), is_valid).encode(env)
}

// #[rustler::nif(schedule = "DirtyCpu")]
// fn get_non_membership_proof<'a>(env: Env<'a>, resource: ResourceArc<AccumulatorResource>, message: Binary) -> Term<'a> {
//   let acc = resource.inner.lock().map_err(|e| {
//     rustler::Error::Term(Box::new(format!(
//         "Could not unlock instance resource as the mutex was poisoned: {e}"
//     )))
//   }).unwrap();

//   // Generate a random 16-byte nonce
//   let mut nonce = [0u8; 16];
//   OsRng.fill_bytes(&mut nonce);

//   let elem = BigInteger::try_from(Vec::from(message.as_slice())).unwrap();
//   match NonMembershipWitness::new_prime(&acc, &elem) {
//     Ok(witness) => {
//       let proof = NonMembershipProof::new(&witness, &acc, &nonce);

//       let proof_bytes: Vec<u8> = proof.to_bytes();
//       let proof_slice = proof_bytes.as_slice();
//       let mut bin = OwnedBinary::new(proof_slice.len()).unwrap();
//       bin.as_mut_slice().copy_from_slice(&proof_slice);
//       let mut nonce_bin = OwnedBinary::new(nonce.len()).unwrap();
//       nonce_bin.as_mut_slice().copy_from_slice(&nonce);
//       (atoms::ok(), Binary::from_owned(bin, env), Binary::from_owned(nonce_bin, env)).encode(env)
//     },
//     Err(e) => (atoms::error(), e.to_string()).encode(env)
//   }
// }

// #[rustler::nif(schedule = "DirtyCpu")]
// fn verify_non_membership_proof<'a>(env: Env<'a>, acc_bytes: Binary, proof_bytes: Binary, nonce: Binary) -> Term<'a> {
//   let acc = match Accumulator::try_from(acc_bytes.as_slice()) {
//     Ok(acc) => acc,
//     Err(_) => return (atoms::error(), "Failed to deserialize the accumulator").encode(env)
//   };

//   let proof = match NonMembershipProof::try_from(proof_bytes.as_slice()) {
//     Ok(proof) => proof,
//     Err(_) => return (atoms::error(), "Failed to deserialize the proof").encode(env)
//   };

//   let is_valid = proof.verify(&acc, nonce.as_slice());
//   (atoms::ok(), is_valid).encode(env)
// }

rustler::init!("Elixir.CryptoAccumulator.Native");