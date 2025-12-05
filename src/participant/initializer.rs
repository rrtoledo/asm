use blake2::digest::Digest;
use digest::FixedOutput;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::bls_multi_signature::{
    BLS_SK_SIZE, BlsSignature, BlsSigningKey, BlsVerificationKeyProofOfPossession, VK_POP_SIZE,
};
use crate::{ClosedKeyRegistration, Index, RegisteredParty, Signer, error::RegisterError};

/// Wrapper of the MultiSignature Verification key with proof of possession
pub type VerificationKeyProofOfPossession = BlsVerificationKeyProofOfPossession;

/// Initializer for `Signer`.
/// This is the data that is used during the key registration procedure.
/// Once the latter is finished, this instance is consumed into an `Signer`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Initializer {
    /// Secret key.
    pub(crate) sk: BlsSigningKey,
    /// Verification (public) key + proof of possession.
    pub(crate) pk: VerificationKeyProofOfPossession,
}

pub const INIT_SIZE: usize = BLS_SK_SIZE + VK_POP_SIZE;

impl Initializer {
    /// Builds an `Initializer` that is ready to register with the key registration service.
    /// This function generates the signing and verification key with a PoP, and initialises the structure.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = BlsSigningKey::generate(rng);
        let pk = VerificationKeyProofOfPossession::from(&sk);
        Self { sk, pk }
    }

    pub fn size() -> usize {
        INIT_SIZE
    }

    /// Extract the verification key with proof of possession.
    pub fn get_verification_key_proof_of_possession(&self) -> VerificationKeyProofOfPossession {
        self.pk
    }

    pub fn prepare_registration(&self) -> Vec<BlsSignature> {
        let index = Index::from_vk(&self.pk.vk);

        let mut index_signatures = Vec::with_capacity(Index::max());

        // We compute H_G1(i)^sk for i != index
        for i in 0..Index::max() {
            if index.to_usize() != i {
                let augmented_index = Index::from_usize(i).augmented_index();
                let signature = self.sk.sign(&augmented_index);
                index_signatures.push(signature);
            } else {
                // This index signature shall remain secret, we replace it with a random signature
                index_signatures.push(BlsSignature(self.pk.pop.get_k1()));
            }
        }

        index_signatures
    }

    /// Create signer from a closed registration if initializer was properly registered.
    pub fn create_signer(self, closed_reg: ClosedKeyRegistration) -> Result<Signer, RegisterError> {
        let index = Index::from_vk(&self.pk.vk);
        let mut index_found = false;

        for (i, rp, _cks) in &closed_reg.registered_parties {
            if rp.pk == self.pk.vk && index == *i {
                index_found = true;
                break;
            }
        }

        if !index_found {
            return Err(RegisterError::UnregisteredInitializer);
        }

        Ok(Signer::set_signer(self.sk, self.pk.vk, closed_reg))
    }

    /// Creates a new basic signer that does not include closed registration.
    /// Takes `eligible_parties` as a parameter and determines the signer's index in the parties.
    /// `eligible_parties` is verified and trusted which is only run by a full-node
    /// that has already verified the parties.
    pub fn create_basic_signer<D: Digest + Clone + FixedOutput>(
        self,
        eligible_parties: &[RegisteredParty],
    ) -> Option<Signer> {
        let mut is_registered = false;

        for rp in eligible_parties {
            if rp.pk == self.pk.vk {
                is_registered = true;
                break;
            }
        }

        if is_registered {
            Some(Signer::set_basic_signer(self.sk, self.pk.vk))
        } else {
            None
        }
    }

    /// Convert to bytes
    /// # Layout
    /// * Secret Key
    /// * Public key (including PoP)
    pub fn to_bytes(&self) -> [u8; INIT_SIZE] {
        let mut out = [0u8; INIT_SIZE];
        out[..BLS_SK_SIZE].copy_from_slice(&self.sk.to_bytes());
        out[BLS_SK_SIZE..].copy_from_slice(&self.pk.to_bytes());
        out
    }

    /// Convert a slice of bytes to an `Initializer`
    /// # Error
    /// The function fails if the given string of bytes is not of required size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Initializer, RegisterError> {
        if bytes.len() != INIT_SIZE {
            return Err(RegisterError::SerializationError);
        }
        let sk = BlsSigningKey::from_bytes(
            bytes
                .get(..BLS_SK_SIZE)
                .ok_or(RegisterError::SerializationError)?,
        )?;
        let pk = VerificationKeyProofOfPossession::from_bytes(
            bytes
                .get(BLS_SK_SIZE..)
                .ok_or(RegisterError::SerializationError)?,
        )?;

        Ok(Self { sk, pk })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls_multi_signature::{
        BlsVerificationKey, helper::unsafe_helpers::vk_from_p2_affine,
    };

    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_bytes() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let init1 = Initializer::new(rng);
        let init1_bytes = init1.to_bytes();
        let init2 = Initializer::from_bytes(&init1_bytes).unwrap();
        assert_eq!(init1.pk, init2.pk);
        assert_eq!(
            vk_from_p2_affine(&BlsVerificationKey(
                init2.sk.to_blst_secret_key().sk_to_pk()
            )),
            vk_from_p2_affine(&init1.pk.vk)
        );
    }
}
