use blake2::{Blake2b, Digest};
use digest::consts::U16;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::bls_multi_signature::{
    BlsSignature, BlsVerificationKey, helper::unsafe_helpers::verify_double_pairing,
};
use crate::error::{BatchedAsmAggregateSignatureError, CoreSignatureError};
use crate::{
    AggregateVerificationKey, AsmAggregateSignatureError, ClosedKeyRegistration, CoreSignature,
    Index, SingleSignature, has_duplicates, hash_index, hash_msg,
};

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
                hasher.update(&[signer]);
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
                hasher.update(&[signer]);
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
                let hashed_indices =
                    AggregateSignature::compute_hash_index(signers_i).mul(&scalar_i);

                batched_key = Some(if let Some(key) = &batched_key {
                    hashed_indices.add(key)
                } else {
                    hashed_indices
                });
            });

        // Verify aggregate signature
        if !verify_double_pairing(
            &closed_reg.aggregate_key.0,
            &self.signature.msg.0,
            &self.signature.rnd,
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

        batched.verify(msg, closed_reg);
        Ok(())
    }
}

/// `AggregateSignature` uses the "concatenation" proving system (as described in Section 4.3 of the original paper.)
/// This means that the aggregated signature contains a vector with all individual signatures.
/// BatchPath is also a part of the aggregate signature which covers path for all signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSignature {
    pub signature: CoreSignature,
    pub signers: Vec<Index>,
}

impl AggregateSignature {
    pub fn aggregate_signatures(
        extended_signatures: Vec<(SingleSignature, BlsVerificationKey)>,
        msg: &[u8],
        closed_reg: &ClosedKeyRegistration,
    ) -> Result<AggregateSignature, AsmAggregateSignatureError> {
        match extended_signatures.len() {
            0 => Err(AsmAggregateSignatureError::NotEnoughSignatures),
            1 => Err(AsmAggregateSignatureError::NotEnoughSignatures),
            l => {
                // Initialize variables
                let mut signature: Option<CoreSignature> = None;
                let mut signers = Vec::<Index>::with_capacity(l);
                let mut vk_hashset = HashSet::<Index>::with_capacity(l);
                let avk = closed_reg.aggregate_key;

                for (sig, vk) in extended_signatures {
                    let keys = closed_reg.get_keys(sig.signer_index);
                    // If the signature's avk is correct and the signer's contribution was not added yet
                    if keys == None
                        || keys.unwrap().0 != vk
                        || vk_hashset.contains(&sig.signer_index)
                    {
                        return Err(AsmAggregateSignatureError::BatchInvalid);
                    }
                    vk_hashset.insert(sig.signer_index);

                    // Verify Single signature (Core signature and signer index are correct)
                    sig.verify(&vk, msg, avk)?;

                    signature = if let Some(acc_sig) = signature {
                        let updated_signature = acc_sig.add_unsafe(&sig.sigma);
                        Some(updated_signature)
                    } else {
                        Some(sig.sigma)
                    };

                    // Updating vk acc
                    signers.push(sig.signer_index);
                }

                Ok(AggregateSignature {
                    signature: signature.unwrap(),
                    signers,
                })
            }
        }
    }

    pub fn update_aggregate(
        &self,
        extended_signatures: Vec<(SingleSignature, BlsVerificationKey)>,
        msg: &[u8],
        closed_reg: &ClosedKeyRegistration,
    ) -> Result<AggregateSignature, AsmAggregateSignatureError> {
        match extended_signatures.len() {
            0 => Err(AsmAggregateSignatureError::NotEnoughSignatures),
            _l => {
                // Initialize variables
                let mut signature = self.signature.clone();
                let mut signers = self.signers.clone();
                let mut vk_hashset = HashSet::<Index>::from_iter(self.signers.clone());
                let avk = closed_reg.aggregate_key;

                for (sig, vk) in extended_signatures {
                    // If the signature's avk is correct and the signer's contribution was not added yet
                    let keys = closed_reg.get_keys(sig.signer_index);
                    if keys == None
                        || keys.unwrap().0 != vk
                        || vk_hashset.contains(&sig.signer_index)
                    {
                        return Err(AsmAggregateSignatureError::BatchInvalid);
                    }
                    vk_hashset.insert(sig.signer_index);

                    // Verify Single signature (Core signature and signer index are correct)
                    sig.verify(&vk, msg, avk)?;

                    // Updating core signature
                    signature = signature.add_unsafe(&sig.sigma);

                    // Updating vk acc
                    signers.push(sig.signer_index);
                }

                Ok(AggregateSignature { signature, signers })
            }
        }
    }

    pub fn merge_aggregates(
        &self,
        asms: Vec<AggregateSignature>,
        msg: &[u8],
        closed_reg: &ClosedKeyRegistration,
    ) -> Result<AggregateSignature, AsmAggregateSignatureError> {
        match asms.len() {
            0 => Err(AsmAggregateSignatureError::NotEnoughAggregates),
            _l => {
                // Initialize variables
                let mut signature = self.signature.clone();
                let mut signers = self.signers.clone();
                let mut vk_hashset = HashSet::<Index>::from_iter(self.signers.clone());

                for asm in asms {
                    // If the signer's contribution was not added yet
                    let asm_hashset = HashSet::<Index>::from_iter(asm.signers.clone());
                    if !vk_hashset.is_disjoint(&asm_hashset) {
                        return Err(AsmAggregateSignatureError::BatchInvalid);
                    }

                    // Verify Aggregate signature (Core signature and signer index are correct)
                    asm.verify(msg, closed_reg.aggregate_key)?;

                    // Updating core signature
                    signature = signature.add_unsafe(&asm.signature);

                    // Updating vk acc and signers set
                    for signer in asm.signers {
                        let _ = vk_hashset.insert(signer);
                        signers.push(signer);
                    }
                }

                Ok(AggregateSignature { signature, signers })
            }
        }
    }

    pub fn compute_hash_index(signers: &[u8]) -> BlsSignature {
        let mut hashed_indices = None;
        for &signer in signers {
            // Combine each signer's index
            let hashed_index = hash_index(signer);
            if hashed_indices.is_none() {
                hashed_indices = Some(hashed_index);
            } else {
                hashed_indices = Some(hashed_index.add(&hashed_indices.unwrap()));
            }
        }
        hashed_indices.unwrap()
    }

    /// Verify aggregate signature, by checking that
    /// * each signature contains only valid indices,
    /// * the lottery is indeed won by each one of them,
    /// * the merkle tree path is valid,
    /// * the aggregate signature validates with respect to the aggregate verification key
    ///   (aggregation is computed using functions `MSP.BKey` and `MSP.BSig` as described in Section 2.4 of the paper).
    pub fn verify(
        &self,
        msg: &[u8],
        avk: AggregateVerificationKey,
    ) -> Result<(), AsmAggregateSignatureError> {
        if self.signers.len() == 0 {
            return Err(AsmAggregateSignatureError::BatchInvalid);
        }

        let hashed_indices = Self::compute_hash_index(&self.signers);

        // Verify aggregate signature
        if !verify_double_pairing(
            &avk.0,
            &self.signature.msg.0,
            &self.signature.rnd,
            &hashed_indices.0,
            &hash_msg(msg).0,
        ) {
            return Err(AsmAggregateSignatureError::BatchInvalid);
        }

        Ok(())
    }

    /// Convert multi signature to bytes
    /// # Layout
    /// * Aggregate signature type (u8)
    /// * Number of the pairs of Signatures and Registered Parties (SigRegParty) (as u64)
    /// * Pairs of Signatures and Registered Parties (prefixed with their size as u64)
    /// * Batch proof
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.signature.to_bytes());
        for &signer in &self.signers {
            out.push(signer);
        }
        out
    }

    ///Extract a `AggregateSignature` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<AggregateSignature, AsmAggregateSignatureError> {
        let mut u64_bytes = [0u8; 96];
        u64_bytes.copy_from_slice(
            bytes
                .get(..96)
                .ok_or(CoreSignatureError::SerializationError)?,
        );
        let signature = CoreSignature::from_bytes(&u64_bytes)?;

        let mut bytes_index = 96;
        let total_signers = (bytes.len() - 96);
        let mut signers = Vec::with_capacity(total_signers);
        for _ in 0..total_signers {
            signers.push(bytes[bytes_index]);
            bytes_index += 1;
        }

        Ok(AggregateSignature { signature, signers })
    }
}
