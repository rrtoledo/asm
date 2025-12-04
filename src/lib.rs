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
//! use rand_core::{RngCore, SeedableRng};
//! use rayon::prelude::*; // We use par_iter to speed things up
//!
//! use mithril_stm::{Clerk, Parameters, SingleSignature, KeyRegistration, Initializer, Signer, AggregationError};
//!
//! let nparties = 4; // Use a small number of parties for this example
//! type D = Blake2b<U32>; // Setting the hash function for convenience
//!
//! let mut rng = ChaCha20Rng::from_seed([0u8; 32]); // create and initialize rng
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
//! // Set low parameters for testing
//! // XXX: not for production
//! let params = Parameters {
//!     m: 100, // Security parameter XXX: not for production
//!     k: 2, // Quorum parameter XXX: not for production
//!     phi_f: 0.2, // Lottery parameter XXX: not for production
//! };
//!
//! // Generate some arbitrary stake for each party
//! // Stake is an integer.
//! // Total stake of all parties is total stake in the system.
//! let stakes = (0..nparties)
//!     .into_iter()
//!     .map(|_| 1 + (rng.next_u64() % 9999))
//!     .collect::<Vec<_>>();
//!
//! // Create a new key registry from the parties and their stake
//! let mut key_reg = KeyRegistration::init();
//!
//! // For each party, crate a Initializer.
//! // This struct can create keys for the party.
//! let mut ps: Vec<Initializer> = Vec::with_capacity(nparties);
//! for stake in stakes {
//!     // Create keys for this party
//!     let p = Initializer::new(params, stake, &mut rng);
//!     // Register keys with the KeyRegistration service
//!     key_reg
//!         .register(p.stake, p.verification_key())
//!         .unwrap();
//!     ps.push(p);
//! }
//!
//! // Close the key registration.
//! let closed_reg = key_reg.close();
//!
//! // Finalize the Initializer and turn it into a Signer, which can execute the
//! // rest of the protocol.
//! let ps = ps
//!     .into_par_iter()
//!     .map(|p| p.new_signer(closed_reg.clone()).unwrap())
//!     .collect::<Vec<Signer<D>>>();
//!
//! /////////////////////
//! // operation phase //
//! /////////////////////
//!
//! // Next, each party tries to sign the message for each index available.
//! // We collect the successful signatures into a vec.
//! let sigs = ps
//!     .par_iter()
//!     .filter_map(|p| {
//!         return p.sign(&msg);
//!     })
//!     .collect::<Vec<SingleSignature>>();
//!
//! // Clerk can aggregate and verify signatures.
//! let clerk = Clerk::from_signer(&ps[0]);
//!
//! // Aggregate and verify the signatures
//! let msig = clerk.aggregate(&sigs, &msg);
//! match msig {
//!     Ok(aggr) => {
//!         println!("Aggregate ok");
//!         assert!(aggr
//!             .verify(&msg, &clerk.compute_avk(), &params)
//!             .is_ok());
//!     }
//!     Err(AggregationError::NotEnoughSignatures(n, k)) => {
//!         println!("Not enough signatures");
//!         assert!(n < params.k && k == params.k)
//!     }
//!     Err(_) => unreachable!(),
//! }
//! # Ok(())
//! # }
//! ```

mod aggregate_signature;
mod bls_multi_signature;
mod error;
mod participant;

pub use aggregate_signature::{AggregateSignature, AggregateVerificationKey, Clerk};
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

use crate::bls_multi_signature::BlsSignature;

/// Compute H1(msg) as H1(msg)^1
pub fn hash_msg(msg: &[u8]) -> BlsSignature {
    let blst_one = {
        let mut one = [0u8; 32];
        one[31] = 1;
        crate::bls_multi_signature::BlsSigningKey::from_bytes(&one)
            .map_err(|_| AsmSignatureError::GenericAsmSignatureError)
            .unwrap()
    };
    let sig = blst_one.to_blst_secret_key().sign(msg, &[], &[]);

    BlsSignature(sig)
}

use std::collections::HashSet;

fn has_duplicates<T: Eq + std::hash::Hash>(v: &[T]) -> bool {
    let mut seen = HashSet::new();
    for item in v {
        if !seen.insert(item) {
            return true;
        }
    }
    false
}
