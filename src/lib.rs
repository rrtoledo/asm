#![doc = include_str!("../README.md")]
//! Implementation of Stake-based Threshold Multisignatures
//! Top-level API for Mithril Stake-based Threshold Multisignature scheme.
//! See figure 6 of [the paper](https://eprint.iacr.org/2021/916) for most of the
//! protocol.
//!
//! What follows is a simple example showing the usage of STM.
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use blake2::{Blake2b, digest::consts::U32};
//! use rand_chacha::ChaCha20Rng;
//! use rand_core::{CryptoRng, RngCore, SeedableRng};
//!
//! use asm::{SingleSignature, VerificationKey, KeyRegistration, Initializer, Signer, AggregateSignature, BatchedAggregateSignature, AsmAggregateSignatureError};
//!
//! let nparties = 9; // Use a small number of parties for this example
//!
//! let rng = &mut ChaCha20Rng::from_seed([0u8; 32]); // create and initialize rng
//! let mut msg = [0u8; 16]; // setting an arbitrary message
//! rng.fill_bytes(&mut msg);
//!
//! // In the following, we will have 4 parties try to sign `msg`, then aggregate and
//! // verify those signatures.
//!
//! //////////////////////////
//! // initialization phase //
//! //////////////////////////
//!
//! // Create a new key registry from the parties and their stake
//! let mut key_reg = KeyRegistration::init();
//!
//! // For each party, crate a Initializer.
//! // This struct can create keys for the party.
//! let mut ps: Vec<Initializer> = Vec::with_capacity(nparties);
//! for _ in 0..nparties {
//!     // Create keys for this party
//!     let p = Initializer::new(rng);
//!     // Create signatures for membership keys
//!     let mks = p.prepare_registration();
//!     // Register keys with the KeyRegistration service
//!     key_reg
//!         .register(p.get_verification_key_proof_of_possession(), &mks)
//!         .unwrap();
//!     ps.push(p);
//! }
//!
//! // Close the key registration.
//! let closed_reg = key_reg.close().unwrap();
//!
//! // Finalize the Initializer and turn it into a Signer, which can execute the
//! // rest of the protocol.
//! let ps = ps
//!     .into_iter()
//!     .map(|p| p.create_signer(closed_reg.clone()).unwrap())
//!     .collect::<Vec<Signer>>();
//!
//! /////////////////////
//! // operation phase //
//! /////////////////////
//!
//! // Next, each party tries to sign the message for each index available.
//! // We collect the successful signatures into a vec.
//! let mut sigs = ps
//!     .iter()
//!     .map(|p| {
//!         (p.sign(&msg, rng).unwrap(), p.get_verification_key())
//!     })
//!     .collect::<Vec<(SingleSignature, VerificationKey)>>();
//!
//! let mut sigs2 = sigs.split_off(3);
//! let sigs3 = sigs2.split_off(3);
//!
//! // Aggregate and verify the signatures
//! let is_aggregated = AggregateSignature::new(sigs, &msg, &closed_reg.clone());
//! match is_aggregated.clone() {
//!     Ok(aggr) => {
//!         println!("Aggregate ok");
//!         assert!(aggr
//!             .verify(&msg, closed_reg.clone().aggregate_key)
//!             .is_ok());
//!     }
//!     Err(AsmAggregateSignatureError::NotEnoughSignatures) => {
//!         println!("Not enough signatures");
//!     }
//!     Err(_) => unreachable!(),
//! }
//!
//! // We are now showing how to merge to aggregates, we could also have updated the former with the extended signatures of the latter
//! let msig1 = is_aggregated.unwrap();
//! let msig2 = [AggregateSignature::new(sigs2, &msg, &closed_reg.clone()).unwrap()].to_vec();
//! let msig = msig1.merge_aggregates(msig2, &msg, &closed_reg.clone()).unwrap();
//!
//! // We are finally showing how to batched aggregates, this should be done on aggregates whose signers intersect however.
//! let msig3 = AggregateSignature::new(sigs3, &msg, &closed_reg.clone()).unwrap();
//! let batched = BatchedAggregateSignature::new( &[msig, msig3], &msg, &closed_reg.clone()).unwrap();
//!
//! assert!(batched.verify(&msg, &closed_reg.clone()).is_ok());
//! # Ok(())
//! # }
//! ```

mod aggregate_signature;
mod bls_multi_signature;
mod error;
mod participant;
pub(crate) mod utils;

pub use aggregate_signature::{
    AggregateSignature, AggregateVerificationKey, BatchedAggregateSignature,
};
pub use error::{AsmAggregateSignatureError, AsmSignatureError, RegisterError};
pub use participant::{
    CS_SIZE, ClosedKeyRegistration, CoreSignature, INDEX_SIZE, Index, Initializer, KeyRegistration,
    RegisteredParty, Signer, SingleSignature, VerificationKey, VerificationKeyProofOfPossession,
};

#[cfg(feature = "benchmark-internals")]
pub use bls_multi_signature::{
    BlsProofOfPossession, BlsSignature, BlsSigningKey, BlsVerificationKey,
    BlsVerificationKeyProofOfPossession,
};
