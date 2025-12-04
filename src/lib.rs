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

use crate::bls_multi_signature::{BlsSignature, helper::unsafe_helpers::fr_one};

/// Compute H1(msg) as H1(msg)^1
pub fn hash_msg(msg: &[u8]) -> BlsSignature {
    let blst_one = fr_one();
    let sig = blst_one.sign(msg, &[], &[]);

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
