use blake2::{Blake2b, Digest};
use digest::consts::U16;
use serde::{Deserialize, Serialize};

use crate::bls_multi_signature::{BlsSignature, helper::unsafe_helpers::verify_double_pairing};
use crate::error::BatchedAsmAggregateSignatureError;
use crate::utils::{compute_hash_index, has_duplicates, hash_msg};
use crate::{AggregateSignature, CS_SIZE, ClosedKeyRegistration, CoreSignature, INDEX_SIZE, Index};

/// `AggregateSignature` uses the "concatenation" proving system (as described in Section 4.3 of the original paper.)
/// This means that the aggregated signature contains a vector with all individual signatures.
/// BatchPath is also a part of the aggregate signature which covers path for all signatures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchedAggregateSignature {
    pub signature: CoreSignature,
    pub signers: Vec<Vec<Index>>,
}

impl BatchedAggregateSignature {
    pub fn new(
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

        let expanded_msg = [msg, &closed_reg.aggregate_key.0.to_bytes()].concat();

        // Verify aggregate signature
        if !verify_double_pairing(
            &closed_reg.aggregate_key.0,
            &self.signature.sig.0,
            &self.signature.vk,
            &batched_key.unwrap().0,
            &hash_msg(&expanded_msg).0,
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
        let batched = Self::new(asms, msg, closed_reg)?;

        batched.verify(msg, closed_reg)
    }

    /// Convert multi signature to bytes
    /// # Layout
    /// * Aggregate signature type (u8)
    /// * Number of the pairs of Signatures and Registered Parties (SigRegParty) (as u64)
    /// * Pairs of Signatures and Registered Parties (prefixed with their size as u64)
    /// * Batch proof
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.signature.to_bytes());
        out.extend_from_slice(&(self.signers.len() as u32).to_be_bytes());
        for signer in self.signers {
            out.extend_from_slice(&(signer.len() as u32).to_be_bytes());
            for s in signer {
                out.extend_from_slice(&s.to_bytes());
            }
        }
        out
    }

    ///Extract a `AggregateSignature` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, BatchedAsmAggregateSignatureError> {
        let mut u64_bytes = [0u8; CS_SIZE];
        u64_bytes.copy_from_slice(
            bytes
                .get(..CS_SIZE)
                .ok_or(BatchedAsmAggregateSignatureError::SerializationError)?,
        );
        let signature = CoreSignature::from_bytes(&u64_bytes)
            .map_err(|_| BatchedAsmAggregateSignatureError::SerializationError)?;

        let mut byte_index = CS_SIZE;
        let total_aggregates =
            u32::from_be_bytes(bytes[byte_index..byte_index + 4].try_into().unwrap());
        byte_index += 4;
        let mut aggregates = Vec::with_capacity(total_aggregates as usize);
        for _ in 0..total_aggregates {
            let nb_signers =
                u32::from_be_bytes(bytes[byte_index..byte_index + 4].try_into().unwrap());
            byte_index += 4;
            let mut signers = Vec::with_capacity(nb_signers as usize);
            for _ in 0..nb_signers {
                let byte_signer_i = &bytes[byte_index..byte_index + INDEX_SIZE];
                byte_index += INDEX_SIZE;
                let signer_i = Index::from_bytes(byte_signer_i);
                if signer_i.is_err() {
                    return Err(BatchedAsmAggregateSignatureError::SerializationError);
                }
                signers.push(signer_i.unwrap());
            }
            aggregates.push(signers);
        }

        Ok(BatchedAggregateSignature {
            signature,
            signers: aggregates,
        })
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
        let signer3 = signers.pop().unwrap();
        let signer4 = signers.pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();

        let sig1 = signer1.sign(&msg, rng).unwrap();
        let sig2 = signer2.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig1, signer1.get_verification_key()),
            (sig2, signer2.get_verification_key()),
        ];
        let agg_sig1 =
            AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry).unwrap();

        let sig3 = signer3.sign(&msg, rng).unwrap();
        let sig4 = signer4.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig3, signer3.get_verification_key()),
            (sig4, signer4.get_verification_key()),
        ];
        let agg_sig2 =
            AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry).unwrap();

        let is_batched = BatchedAggregateSignature::new(&[agg_sig1, agg_sig2], &msg, &registry);
        assert!(is_batched.is_ok());

        let batched_sig = is_batched.unwrap();
        assert!(batched_sig.verify(&msg, &registry).is_ok());
    }

    #[test]
    fn test_batch_negative() {
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
        let agg_sig1 =
            AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry).unwrap();

        let msg = rng.next_u32().to_be_bytes();

        let sig3 = signer3.sign(&msg, rng).unwrap();
        let sig4 = signer4.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig3, signer3.get_verification_key()),
            (sig4, signer4.get_verification_key()),
        ];
        let agg_sig2 =
            AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry).unwrap();

        let is_batched = BatchedAggregateSignature::new(&[agg_sig1, agg_sig2], &msg, &registry);
        assert!(is_batched.is_err());
    }

    #[test]
    fn test_bytes() {
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
        let agg_sig1 =
            AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry).unwrap();

        let sig3 = signer3.sign(&msg, rng).unwrap();
        let sig4 = signer4.sign(&msg, rng).unwrap();
        let extended_signatures = [
            (sig3, signer3.get_verification_key()),
            (sig4, signer4.get_verification_key()),
        ];
        let agg_sig2 =
            AggregateSignature::new(extended_signatures.to_vec(), &msg, &registry).unwrap();

        let batched_sig =
            BatchedAggregateSignature::new(&[agg_sig1, agg_sig2], &msg, &registry).unwrap();

        let batched_sig_bytes = batched_sig.clone().to_bytes();
        assert_eq!(
            batched_sig,
            BatchedAggregateSignature::from_bytes(&batched_sig_bytes).unwrap()
        );
    }
}
