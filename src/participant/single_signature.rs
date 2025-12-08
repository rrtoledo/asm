use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};

use crate::bls_multi_signature::helper::unsafe_helpers::verify_double_pairing;
use crate::utils::hash_msg;
use crate::{AggregateVerificationKey, AsmSignatureError, CoreSignature, Index, VerificationKey};

/// Signature created by a single party that is registered.
/// The underlying core signature has been udpated with the membership key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleSignature {
    /// The signature.
    pub sigma: CoreSignature,
    /// Signer's index
    pub signer_index: Index,
}

impl SingleSignature {
    /// Verify an ASM signature by checking that the signature verifies on a
    /// message augmented with an aggregate key.
    pub fn verify(
        &self,
        pk: &VerificationKey,
        msg: &[u8],
        avk: AggregateVerificationKey,
    ) -> Result<(), AsmSignatureError> {
        // Verify signature on augmented message
        let augmented_message: Vec<u8> = [msg, &avk.0.to_bytes()].concat();
        self.basic_verify(pk, &augmented_message, avk)?;
        Ok(())
    }

    /// Verify a single signature by checking that the index is correct and
    /// that the underlying core signature validates.
    pub(crate) fn basic_verify(
        &self,
        pk: &VerificationKey,
        msg: &[u8],
        avk: AggregateVerificationKey,
    ) -> Result<(), AsmSignatureError> {
        // Verify signer's index is correct
        let index = Index::from_vk(pk);
        if index != self.signer_index {
            return Err(AsmSignatureError::SignatureIndexInvalid);
        }

        // Verifying that the core signature with membership key verifiees
        if !verify_double_pairing(
            &avk.0,
            &self.sigma.sig.0,
            &self.sigma.vk,
            &index.hash_to_g1().0,
            &hash_msg(msg).0,
        ) {
            return Err(AsmSignatureError::SignatureInvalid);
        }

        Ok(())
    }

    pub fn size() -> usize {
        CoreSignature::size() + Index::size()
    }

    /// Convert an `SingleSignature` into bytes
    ///
    /// # Layout
    /// * Signer Index
    /// * Core Signature:
    /// ** vk as element of G2
    /// ** sig as element of G1
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&self.signer_index.to_bytes());
        output.extend_from_slice(&self.sigma.to_bytes());
        output
    }

    /// Extract a batch compatible `SingleSignature` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<SingleSignature, AsmSignatureError> {
        let signer_index = Index::from_bytes(&[bytes[0]]);
        if signer_index.is_err() {
            return Err(AsmSignatureError::SerializationError);
        }

        let sigma_res = CoreSignature::from_bytes(&bytes[1..]);

        sigma_res.map(|sigma| SingleSignature {
            signer_index: signer_index.unwrap(),
            sigma,
        })
    }
}

impl Hash for SingleSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut data = Vec::new();
        data.extend_from_slice(&self.signer_index.to_bytes());
        data.extend_from_slice(&self.sigma.to_bytes());
        Hash::hash_slice(&data, state)
    }
}

impl PartialEq for SingleSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sigma == other.sigma && self.signer_index == other.signer_index
    }
}

impl Eq for SingleSignature {}

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

        let nb_signers = 2;

        let (registry, signers) = prepare_signers(nb_signers, rng);
        let avk = registry.aggregate_key;
        let signer = signers.clone().pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();
        let signing = signer.sign(&msg, rng);
        assert!(signing.is_ok());
        let sig = signing.unwrap();
        assert!(
            sig.verify(&signer.get_verification_key(), &msg, avk)
                .is_ok()
        );
    }

    #[test]
    fn test_bytes() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let nb_signers = 2;
        let (_registry, signers) = prepare_signers(nb_signers, rng);
        let signer = signers.clone().pop().unwrap();

        let msg = rng.next_u32().to_be_bytes();
        let signing = signer.sign(&msg, rng);
        assert!(signing.is_ok());
        let sig = signing.unwrap();

        let sig_bytes = sig.to_bytes();
        assert_eq!(sig, SingleSignature::from_bytes(&sig_bytes).unwrap());
    }
}
