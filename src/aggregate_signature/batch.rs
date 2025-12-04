use blake2::{Blake2b, Digest};
use digest::consts::U16;
use serde::{Deserialize, Serialize};

use crate::bls_multi_signature::{BlsSignature, helper::unsafe_helpers::verify_double_pairing};
use crate::error::BatchedAsmAggregateSignatureError;
use crate::{
    AggregateSignature, ClosedKeyRegistration, CoreSignature, Index, has_duplicates, hash_msg,
};

use super::utils::compute_hash_index;

/// `AggregateSignature` uses the "concatenation" proving system (as described in Section 4.3 of the original paper.)
/// This means that the aggregated signature contains a vector with all individual signatures.
/// BatchPath is also a part of the aggregate signature which covers path for all signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchedAggregateSignature {
    pub signature: CoreSignature,
    pub signers: Vec<Vec<Index>>,
}

impl BatchedAggregateSignature {
    pub fn batch(
        asms: &[AggregateSignature],
        msg: &[u8],
        closed_reg: &ClosedKeyRegistration,
    ) -> Result<Self, BatchedAsmAggregateSignatureError> {
        if asms.len() < 2 {
            return Err(BatchedAsmAggregateSignatureError::NotEnoughAggregates);
        }

        for asm in asms {
            asm.verify(msg, closed_reg.aggregate_key)?;
        }

        Ok(Self::batch_unsafe(asms))
    }

    pub fn batch_unsafe(asms: &[AggregateSignature]) -> Self {
        let mut scalars = Vec::with_capacity(asms.len() * 128);

        let mut hasher = Blake2b::<U16>::new();
        let mut signers = Vec::with_capacity(asms.len());

        // Initializing the hasher with all signers making sure to separate the asm with a counter
        // and collecting all signers in vector
        for (i, asm) in asms.iter().enumerate() {
            let signers_i = asm.signers.clone();
            signers.push(signers_i.clone());

            hasher.update(i.to_be_bytes());
            for signer in signers_i.clone() {
                hasher.update(signer.to_bytes());
            }
        }

        // Generating the scalars
        for i in 0..asms.len() {
            hasher.update(i.to_be_bytes());
            let hash_scalar = hasher.clone();
            scalars.push(hash_scalar.finalize().to_vec());
        }

        // MSM on CoreSignatures and Scalars
        let mut signature: Option<CoreSignature> = None;
        asms.iter().zip(scalars).for_each(|(asm_i, scalar_i)| {
            let randomized_sig = asm_i.signature.clone().multiply(&scalar_i);

            signature = Some(if let Some(sig) = &signature {
                randomized_sig.add_unsafe(sig)
            } else {
                randomized_sig
            });
        });

        BatchedAggregateSignature {
            signature: signature.unwrap(),
            signers,
        }
    }

    /// Batch verify a set of signatures, with different messages and avks.
    pub fn verify(
        self,
        msg: &[u8],
        closed_reg: &ClosedKeyRegistration,
    ) -> Result<(), BatchedAsmAggregateSignatureError> {
        let mut scalars = Vec::with_capacity(self.signers.len() * 128);

        let mut hasher = Blake2b::<U16>::new();
        for (i, signers) in self.signers.iter().enumerate() {
            let signers_i = signers.clone();
            if has_duplicates(&signers_i) {
                return Err(BatchedAsmAggregateSignatureError::BatchInvalid);
            }

            hasher.update(i.to_be_bytes());
            for signer in signers_i.clone() {
                hasher.update(signer.to_bytes());
            }
        }

        // Generating the scalars
        for i in 0..self.signers.len() {
            hasher.update(i.to_be_bytes());
            let hash_scalar = hasher.clone();
            scalars.push(hash_scalar.finalize().to_vec());
        }

        // Compute batched key
        let mut batched_key: Option<BlsSignature> = None;
        self.signers
            .iter()
            .zip(scalars)
            .for_each(|(signers_i, scalar_i)| {
                let hashed_indices = compute_hash_index(signers_i).mul(&scalar_i);

                batched_key = Some(if let Some(key) = &batched_key {
                    hashed_indices.add(key)
                } else {
                    hashed_indices
                });
            });

        // Verify aggregate signature
        if !verify_double_pairing(
            &closed_reg.aggregate_key.0,
            &self.signature.sig.0,
            &self.signature.vk,
            &batched_key.unwrap().0,
            &hash_msg(msg).0,
        ) {
            return Err(BatchedAsmAggregateSignatureError::BatchInvalid);
        }

        Ok(())
    }

    /// Batch verify a set of signatures, with different messages and avks.
    pub fn batch_verify(
        asms: &[AggregateSignature],
        msg: &[u8],
        closed_reg: &ClosedKeyRegistration,
    ) -> Result<(), BatchedAsmAggregateSignatureError> {
        let batched = Self::batch(asms, msg, closed_reg)?;

        batched.verify(msg, closed_reg)
    }
}
