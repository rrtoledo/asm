use blake2::digest::{Digest, FixedOutput};

use serde::{Deserialize, Serialize};

use crate::bls_multi_signature::{BlsSignature, BlsVerificationKey, helper::unsafe_helpers::verify_double_pairing};
use crate::key_registration::RegisteredParty;
use crate::{
    AggregateVerificationKey, AsmAggregateSignatureError, BasicVerifier, ClosedKeyRegistration,
    CoreSignature, Index, SingleSignature, hash_index, hash_msg
};

use std::collections::HashSet;

/// `AggregateSignature` uses the "concatenation" proving system (as described in Section 4.3 of the original paper.)
/// This means that the aggregated signature contains a vector with all individual signatures.
/// BatchPath is also a part of the aggregate signature which covers path for all signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchedAggregateSignature {
    pub signature: CoreSignature,
    pub signers: Vec<Vec<Index>>,
}

impl BatchedAggregateSignature {
    pub fn batch(asms: &[AggregateSignature],
    msg: &[u8],
    closed_ref: &ClosedKeyRegistration) -> Self {
        !panic!("todo")
    }

    pub fn batch_unsafe(asms: &[AggregateSignature]) -> Self {
        !panic!("todo")
    }

    /// Batch verify a set of signatures, with different messages and avks.
    pub fn verify(
        self,
        msgs: &[u8],
        closed_reg: &ClosedKeyRegistration,
    ) -> Result<(), AsmAggregateSignatureError> {
        let batch_size = stm_signatures.len();
        assert_eq!(
            batch_size,
            msgs.len(),
            "Number of messages should correspond to size of the batch"
        );
        assert_eq!(
            batch_size,
            avks.len(),
            "Number of avks should correspond to size of the batch"
        );
        assert_eq!(
            batch_size,
            parameters.len(),
            "Number of parameters should correspond to size of the batch"
        );

        let mut aggr_sigs = Vec::with_capacity(batch_size);
        let mut aggr_vks = Vec::with_capacity(batch_size);
        for (idx, sig_group) in stm_signatures.iter().enumerate() {
            sig_group.preliminary_verify(&msgs[idx], &avks[idx], &parameters[idx])?;
            let grouped_sigs: Vec<BlsSignature> = sig_group
                .signatures
                .iter()
                .map(|sig_reg| sig_reg.sig.sigma)
                .collect();
            let grouped_vks: Vec<BlsVerificationKey> = sig_group
                .signatures
                .iter()
                .map(|sig_reg| sig_reg.reg_party.0)
                .collect();

            let (aggr_vk, aggr_sig) = BlsSignature::aggregate(&grouped_vks, &grouped_sigs).unwrap();
            aggr_sigs.push(aggr_sig);
            aggr_vks.push(aggr_vk);
        }

        let concat_msgs: Vec<Vec<u8>> = msgs
            .iter()
            .zip(avks.iter())
            .map(|(msg, avk)| {
                avk.get_merkle_tree_batch_commitment()
                    .concatenate_with_message(msg)
            })
            .collect();

        BlsSignature::batch_verify_aggregates(&concat_msgs, &aggr_vks, &aggr_sigs)?;
        Ok(())
    }

    /// Batch verify a set of signatures, with different messages and avks.
    pub fn batch_verify(
        basm: &[Self],
        msgs: &[u8],
        avks: &[AggregateVerificationKey<D>],
    ) -> Result<(), AsmAggregateSignatureError> {
        let batch_size = stm_signatures.len();
        assert_eq!(
            batch_size,
            msgs.len(),
            "Number of messages should correspond to size of the batch"
        );
        assert_eq!(
            batch_size,
            avks.len(),
            "Number of avks should correspond to size of the batch"
        );
        assert_eq!(
            batch_size,
            parameters.len(),
            "Number of parameters should correspond to size of the batch"
        );

        let mut aggr_sigs = Vec::with_capacity(batch_size);
        let mut aggr_vks = Vec::with_capacity(batch_size);
        for (idx, sig_group) in stm_signatures.iter().enumerate() {
            sig_group.preliminary_verify(&msgs[idx], &avks[idx], &parameters[idx])?;
            let grouped_sigs: Vec<BlsSignature> = sig_group
                .signatures
                .iter()
                .map(|sig_reg| sig_reg.sig.sigma)
                .collect();
            let grouped_vks: Vec<BlsVerificationKey> = sig_group
                .signatures
                .iter()
                .map(|sig_reg| sig_reg.reg_party.0)
                .collect();

            let (aggr_vk, aggr_sig) = BlsSignature::aggregate(&grouped_vks, &grouped_sigs).unwrap();
            aggr_sigs.push(aggr_sig);
            aggr_vks.push(aggr_vk);
        }

        let concat_msgs: Vec<Vec<u8>> = msgs
            .iter()
            .zip(avks.iter())
            .map(|(msg, avk)| {
                avk.get_merkle_tree_batch_commitment()
                    .concatenate_with_message(msg)
            })
            .collect();

        BlsSignature::batch_verify_aggregates(&concat_msgs, &aggr_vks, &aggr_sigs)?;
        Ok(())
    }
}

/// `AggregateSignature` uses the "concatenation" proving system (as described in Section 4.3 of the original paper.)
/// This means that the aggregated signature contains a vector with all individual signatures.
/// BatchPath is also a part of the aggregate signature which covers path for all signatures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSignature {
    pub signature: CoreSignature,
    pub avk: AggregateVerificationKey,
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
                    avk,
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

                Ok(AggregateSignature {
                    signature,
                    avk: self.avk,
                    signers,
                })
            }
        }
    }

    pub fn merge_aggregates(
        &self,
        asms: Vec<AggregateSignature>,
        msg: &[u8],
        closed_reg: &ClosedKeyRegistration
    ) -> Result<AggregateSignature, AsmAggregateSignatureError> {
        match asms.len() {
            0 => Err(AsmAggregateSignatureError::NotEnoughAggregates),
            _l => {
                // Initialize variables
                let mut signature = self.signature.clone();
                let mut signers = self.signers.clone();
                let mut vk_hashset = HashSet::<Index>::from_iter(self.signers.clone());

                for asm in asms {
                    // If the signature's avk is correct and the signer's contribution was not added yet
                    let asm_hashset = HashSet::<Index>::from_iter(asm.signers.clone());
                    if asm.avk != self.avk || !vk_hashset.is_disjoint(&asm_hashset) {
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

                Ok(AggregateSignature {
                    signature,
                    avk: self.avk,
                    signers,
                })
            }
        }
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
        let signers = self.signers.clone();
        if self.signers.len() == 0 {
            return Err(AsmAggregateSignatureError::BatchInvalid);
        }

        let mut hashed_indices = None;
        for signer in signers {

            // Combine each signer's index
            let hashed_index = hash_index(signer);
            if hashed_indices.is_none() {
                hashed_indices = Some(hashed_index);
            } else {
                hashed_indices = Some(hashed_index.add(&hashed_indices.unwrap()));
            }
        }

        // Verify aggregate signature
        if !verify_double_pairing(
            &avk.0,
            &self.signature.msg.0,
            &self.signature.rnd,
            &hashed_indices.unwrap().0,
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
        // This proof type is not strictly necessary, but it will help to identify
        // the type of the proof used to aggregate when implementing multiple aggregation proof systems.
        // We use '0' for concatenation proof.
        let proof_type: u8 = 0;
        out.extend_from_slice(&proof_type.to_be_bytes());
        out.extend_from_slice(&u64::try_from(self.signatures.len()).unwrap().to_be_bytes());
        for sig_reg in &self.signatures {
            out.extend_from_slice(
                &u64::try_from(sig_reg.to_bytes().len())
                    .unwrap()
                    .to_be_bytes(),
            );
            out.extend_from_slice(&sig_reg.to_bytes());
        }
        let proof = &self.batch_proof;
        out.extend_from_slice(&proof.to_bytes());

        out
    }

    ///Extract a `AggregateSignature` from a byte slice.
    pub fn from_bytes(
        bytes: &[u8],
    ) -> Result<AggregateSignature<D>, StmAggregateSignatureError<D>> {
        let mut u8_bytes = [0u8; 1];
        let mut bytes_index = 0;

        u8_bytes.copy_from_slice(
            bytes
                .get(..1)
                .ok_or(StmAggregateSignatureError::SerializationError)?,
        );
        bytes_index += 1;
        let proof_type = u8::from_be_bytes(u8_bytes);
        if proof_type != 0 {
            return Err(StmAggregateSignatureError::SerializationError);
        }

        let mut u64_bytes = [0u8; 8];
        u64_bytes.copy_from_slice(
            bytes
                .get(bytes_index..bytes_index + 8)
                .ok_or(StmAggregateSignatureError::SerializationError)?,
        );
        let total_sigs = usize::try_from(u64::from_be_bytes(u64_bytes))
            .map_err(|_| StmAggregateSignatureError::SerializationError)?;
        bytes_index += 8;

        let mut sig_reg_list = Vec::with_capacity(total_sigs);
        for _ in 0..total_sigs {
            u64_bytes.copy_from_slice(
                bytes
                    .get(bytes_index..bytes_index + 8)
                    .ok_or(StmAggregateSignatureError::SerializationError)?,
            );
            let sig_reg_size = usize::try_from(u64::from_be_bytes(u64_bytes))
                .map_err(|_| StmAggregateSignatureError::SerializationError)?;
            let sig_reg = SingleSignatureWithRegisteredParty::from_bytes::<D>(
                bytes
                    .get(bytes_index + 8..bytes_index + 8 + sig_reg_size)
                    .ok_or(StmAggregateSignatureError::SerializationError)?,
            )?;
            bytes_index += 8 + sig_reg_size;
            sig_reg_list.push(sig_reg);
        }

        let batch_proof = MerkleBatchPath::from_bytes(
            bytes
                .get(bytes_index..)
                .ok_or(StmAggregateSignatureError::SerializationError)?,
        )?;

        Ok(AggregateSignature {
            signatures: sig_reg_list,
            batch_proof,
        })
    }
}
