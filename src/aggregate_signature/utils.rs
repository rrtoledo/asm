use crate::Index;
use crate::bls_multi_signature::BlsSignature;

pub fn compute_hash_index(signers: &[Index]) -> BlsSignature {
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
