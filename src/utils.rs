use crate::Index;
use crate::bls_multi_signature::{BlsSignature, helper::unsafe_helpers::fr_one};

use std::collections::HashSet;

// Compute Π_i H_G1(index_i)
pub(crate) fn compute_hash_index(signers: &[Index]) -> BlsSignature {
    let mut hashed_indices = None;
    for &signer in signers {
        // Combine each signer's index
        let hashed_index = signer.hash_to_g1();
        if hashed_indices.is_none() {
            hashed_indices = Some(hashed_index);
        } else {
            hashed_indices = Some(hashed_index.add(&hashed_indices.unwrap()));
        }
    }
    hashed_indices.unwrap()
}

// Check if a vector has duplicate elements.
pub(crate) fn has_duplicates<T: Eq + std::hash::Hash>(v: &[T]) -> bool {
    let mut seen = HashSet::new();
    for item in v {
        if !seen.insert(item) {
            return true;
        }
    }
    false
}

/// Compute H1(msg) as H1(msg)^1
pub fn hash_msg(msg: &[u8]) -> BlsSignature {
    let blst_one = fr_one();
    let sig = blst_one.sign(msg, &[], &[]);

    BlsSignature(sig)
}
