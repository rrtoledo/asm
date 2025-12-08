use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::bls_multi_signature::{
    BlsVerificationKey, helper::unsafe_helpers::verify_double_pairing,
};
use crate::error::CoreSignatureError;
use crate::utils::{compute_hash_index, hash_msg};
use crate::{
    AggregateVerificationKey, AsmAggregateSignatureError, CS_SIZE, ClosedKeyRegistration,
    CoreSignature, INDEX_SIZE, Index, SingleSignature,
};

/// `AggregateSignature` aggregate several SingleSignatures into a
/// CoreSignature and vector of signers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateSignature {
    pub signature: CoreSignature,
    pub signers: Vec<Index>,
}

impl AggregateSignature {
    // Aggregate several SingleSignatures on the same message if there os no
    // duplicate signers, the signatures verify and their corresponding vk was
    // registered.
    pub fn new(
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
                    if sig.verify(&vk, msg, avk).is_err() {
                        return Err(AsmAggregateSignatureError::BatchInvalid);
                    }

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

    // Update an AggregateSignature with several SingleSignatures on the same
    // message if there is no duplicate signers, the signatures verify and their
    // corresponding vk was registered.
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

    // Merge AggregateSignatures on the same message together if there is no
    // duplicate signers, the signatures verify and their corresponding vk was
    // registered.
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

        let hashed_indices = compute_hash_index(&self.signers);
        let expanded_msg = [msg, &avk.0.to_bytes()].concat();

        // Verify aggregate signature
        if !verify_double_pairing(
            &avk.0,
            &self.signature.sig.0,
            &self.signature.vk,
            &hashed_indices.0,
            &hash_msg(&expanded_msg).0,
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
            out.extend_from_slice(&signer.to_bytes());
        }
        out
    }

    ///Extract a `AggregateSignature` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<AggregateSignature, AsmAggregateSignatureError> {
        let mut u64_bytes = [0u8; CS_SIZE];
        u64_bytes.copy_from_slice(
            bytes
                .get(..CS_SIZE)
                .ok_or(CoreSignatureError::SerializationError)?,
        );
        let signature = CoreSignature::from_bytes(&u64_bytes)?;

        let total_signers = (bytes.len() - CS_SIZE) / INDEX_SIZE;
        let mut signers = Vec::with_capacity(total_signers);
        for i in 0..total_signers {
            let byte_signer_i = &bytes[CS_SIZE + i * INDEX_SIZE..CS_SIZE + (i + 1) * INDEX_SIZE];
            let signer_i = Index::from_bytes(byte_signer_i);
            if signer_i.is_err() {
                return Err(AsmAggregateSignatureError::SerializationError);
            }
            signers.push(signer_i.unwrap());
        }

        Ok(AggregateSignature { signature, signers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ClosedKeyRegistration, Initializer, KeyRegistration, Signer};

    use rand_chacha::ChaCha20Rng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};

    fn prepare_signers<R: RngCore + CryptoRng>(
        nb_signers: usize,
        rng: &mut R,
    ) -> (ClosedKeyRegistration, Vec<Signer>) {
        let mut key_reg = KeyRegistration::init();

        // Create signers and pre-register them
        let mut inits = Vec::with_capacity(nb_signers);
        for _ in 0..nb_signers {
            let init = Initializer::new(rng);
            let preregistered =
                key_reg.pre_register(init.get_verification_key_proof_of_possession());
            assert!(preregistered.is_ok());
            inits.push(init);
        }

        // Close pre-registration
        let indices: Vec<Index> = key_reg.close_preregistration();

        // Sharing signatures on preregistered indices to register
        for init in &inits {
            let mks = init.prepare_registration(&indices);
            let registered = key_reg.register(init.get_vk(), &mks);
            assert!(registered.is_ok());
        }

        // Closing registration
        let is_closed = key_reg.close();
        assert!(is_closed.is_ok());
        let registry = is_closed.unwrap();

        // Retrieving the membership keys to create signers
        let signers: Vec<Signer> = inits
            .iter()
            .map(|init| {
                let is_signed = init.clone().create_signer(registry.clone());
                assert!(is_signed.is_ok());
                is_signed.unwrap()
            })
            .collect();

        (registry, signers)
    }

    #[test]
    fn test_verify() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let nb_signers = 4;

        let (registry, signers_immu) = prepare_signers(nb_signers, rng);
        let mut signers = signers_immu.clone();
        let signer1 = signers.pop().unwrap();
        let signer2 = signers.pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();
        let sig1 = signer1.sign(&msg, rng).unwrap();
        let sig2 = signer2.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig1, signer1.get_verification_key()),
            (sig2, signer2.get_verification_key()),
        ];

        let is_aggregated = AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig = is_aggregated.unwrap();

        assert!(agg_sig.verify(&msg, registry.aggregate_key).is_ok());
    }

    #[test]
    fn test_update_positive() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let nb_signers = 4;

        let (registry, signers_immu) = prepare_signers(nb_signers, rng);
        let mut signers = signers_immu.clone();
        let signer1 = signers.pop().unwrap();
        let signer2 = signers.pop().unwrap();
        let signer3 = signers.pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();
        let sig1 = signer1.sign(&msg, rng).unwrap();
        let sig2 = signer2.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig1, signer1.get_verification_key()),
            (sig2, signer2.get_verification_key()),
        ];

        let is_aggregated = AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig = is_aggregated.unwrap();

        assert!(agg_sig.verify(&msg, registry.aggregate_key).is_ok());

        let sig3 = signer3.sign(&msg, rng).unwrap();
        let other_sigs = [(sig3, signer3.get_verification_key())];

        let is_updated = agg_sig.update_aggregate(other_sigs.to_vec(), &msg, &registry);
        assert!(is_updated.is_ok());
        let agg_sig = is_updated.unwrap();

        assert!(agg_sig.verify(&msg, registry.aggregate_key).is_ok());
    }

    #[test]
    fn test_update_negative_msg() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let nb_signers = 4;

        let (registry, signers_immu) = prepare_signers(nb_signers, rng);
        let mut signers = signers_immu.clone();
        let signer1 = signers.pop().unwrap();
        let signer2 = signers.pop().unwrap();
        let signer3 = signers.pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();
        let sig1 = signer1.sign(&msg, rng).unwrap();
        let sig2 = signer2.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig1, signer1.get_verification_key()),
            (sig2, signer2.get_verification_key()),
        ];

        let is_aggregated = AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig = is_aggregated.unwrap();

        assert!(agg_sig.verify(&msg, registry.aggregate_key).is_ok());

        let msg = rng.next_u32().to_be_bytes();
        let sig3 = signer3.sign(&msg, rng).unwrap();
        let other_sigs = [(sig3, signer3.get_verification_key())];

        let is_updated = agg_sig.update_aggregate(other_sigs.to_vec(), &msg, &registry);
        assert!(is_updated.is_ok());
        let agg_sig = is_updated.unwrap();

        assert!(agg_sig.verify(&msg, registry.aggregate_key).is_err());
    }

    #[test]
    fn test_update_negative_sig() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let nb_signers = 4;

        let (registry, signers_immu) = prepare_signers(nb_signers, rng);
        let mut signers = signers_immu.clone();
        let signer1 = signers.pop().unwrap();
        let signer2 = signers.pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();
        let sig1 = signer1.sign(&msg, rng).unwrap();
        let sig2 = signer2.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig1, signer1.get_verification_key()),
            (sig2, signer2.get_verification_key()),
        ];

        let is_aggregated = AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig = is_aggregated.unwrap();

        assert!(agg_sig.verify(&msg, registry.aggregate_key).is_ok());

        let msg = rng.next_u32().to_be_bytes();
        let sig3 = signer2.sign(&msg, rng).unwrap();
        let other_sigs = [(sig3, signer2.get_verification_key())];

        let is_updated = agg_sig.update_aggregate(other_sigs.to_vec(), &msg, &registry);
        assert!(is_updated.is_err());
    }

    #[test]
    fn test_merge_positive() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let nb_signers = 4;

        let (registry, signers_immu) = prepare_signers(nb_signers, rng);
        let mut signers = signers_immu.clone();
        let signer1 = signers.pop().unwrap();
        let signer2 = signers.pop().unwrap();
        let signer3 = signers.pop().unwrap();
        let signer4 = signers.pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();

        let sig1 = signer1.sign(&msg, rng).unwrap();
        let sig2 = signer2.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig1, signer1.get_verification_key()),
            (sig2, signer2.get_verification_key()),
        ];
        let is_aggregated = AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig1 = is_aggregated.unwrap();
        assert!(agg_sig1.verify(&msg, registry.aggregate_key).is_ok());

        let sig3 = signer3.sign(&msg, rng).unwrap();
        let sig4 = signer4.sign(&msg, rng).unwrap();
        let other_sigs = [
            (sig3, signer3.get_verification_key()),
            (sig4, signer4.get_verification_key()),
        ];
        let is_aggregated = AggregateSignature::new(other_sigs.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig2 = is_aggregated.unwrap();

        let is_merged = agg_sig1.merge_aggregates([agg_sig2].to_vec(), &msg, &registry);
        assert!(is_merged.is_ok());
        let agg_sig = is_merged.unwrap();

        assert!(agg_sig.verify(&msg, registry.aggregate_key).is_ok());
    }

    #[test]
    fn test_merge_negative_msg() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let nb_signers = 4;

        let (registry, signers_immu) = prepare_signers(nb_signers, rng);
        let mut signers = signers_immu.clone();
        let signer1 = signers.pop().unwrap();
        let signer2 = signers.pop().unwrap();
        let signer3 = signers.pop().unwrap();
        let signer4 = signers.pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();

        let sig1 = signer1.sign(&msg, rng).unwrap();
        let sig2 = signer2.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig1, signer1.get_verification_key()),
            (sig2, signer2.get_verification_key()),
        ];
        let is_aggregated = AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig1 = is_aggregated.unwrap();
        assert!(agg_sig1.verify(&msg, registry.aggregate_key).is_ok());

        let msg = rng.next_u32().to_be_bytes();

        let sig3 = signer3.sign(&msg, rng).unwrap();
        let sig4 = signer4.sign(&msg, rng).unwrap();
        let other_sigs = [
            (sig3, signer3.get_verification_key()),
            (sig4, signer4.get_verification_key()),
        ];
        let is_aggregated = AggregateSignature::new(other_sigs.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig2 = is_aggregated.unwrap();

        let is_merged = agg_sig1.merge_aggregates([agg_sig2].to_vec(), &msg, &registry);
        assert!(is_merged.is_ok());
        let agg_sig = is_merged.unwrap();

        assert!(agg_sig.verify(&msg, registry.aggregate_key).is_err());
    }

    #[test]
    fn test_merge_negative_sig() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let nb_signers = 4;

        let (registry, signers_immu) = prepare_signers(nb_signers, rng);
        let mut signers = signers_immu.clone();
        let signer1 = signers.pop().unwrap();
        let signer2 = signers.pop().unwrap();
        let signer3 = signers.pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();

        let sig1 = signer1.sign(&msg, rng).unwrap();
        let sig2 = signer2.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig1, signer1.get_verification_key()),
            (sig2, signer2.get_verification_key()),
        ];
        let is_aggregated = AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig1 = is_aggregated.unwrap();
        assert!(agg_sig1.verify(&msg, registry.aggregate_key).is_ok());

        let msg = rng.next_u32().to_be_bytes();

        let sig3 = signer3.sign(&msg, rng).unwrap();
        let sig4 = signer2.sign(&msg, rng).unwrap();
        let other_sigs = [
            (sig3, signer3.get_verification_key()),
            (sig4, signer2.get_verification_key()),
        ];
        let is_aggregated = AggregateSignature::new(other_sigs.to_vec(), &msg, &registry);
        assert!(is_aggregated.is_ok());
        let agg_sig2 = is_aggregated.unwrap();

        let is_merged = agg_sig1.merge_aggregates([agg_sig2].to_vec(), &msg, &registry);
        assert!(is_merged.is_err());
    }

    #[test]
    fn test_bytes() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let nb_signers = 2;

        let (registry, signers_immu) = prepare_signers(nb_signers, rng);
        let mut signers = signers_immu.clone();
        let signer1 = signers.pop().unwrap();
        let signer2 = signers.pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();
        let sig1 = signer1.sign(&msg, rng).unwrap();
        let sig2 = signer2.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig1, signer1.get_verification_key()),
            (sig2, signer2.get_verification_key()),
        ];

        let agg_sig =
            AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry).unwrap();

        let agg_sig_bytes = agg_sig.to_bytes();
        assert_eq!(
            agg_sig,
            AggregateSignature::from_bytes(&agg_sig_bytes).unwrap()
        );
    }
}
