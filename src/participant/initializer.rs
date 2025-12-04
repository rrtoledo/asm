use blake2::digest::Digest;
use digest::FixedOutput;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::bls_multi_signature::{BlsSigningKey, BlsVerificationKeyProofOfPossession};
use crate::{Signer, error::RegisterError};
use crate::{get_index, key_registration::*};

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

impl Initializer {
    /// Builds an `Initializer` that is ready to register with the key registration service.
    /// This function generates the signing and verification key with a PoP, and initialises the structure.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let sk = BlsSigningKey::generate(rng);
        let pk = VerificationKeyProofOfPossession::from(&sk);
        Self { sk, pk }
    }

    /// Extract the verification key with proof of possession.
    pub fn get_verification_key_proof_of_possession(&self) -> VerificationKeyProofOfPossession {
        self.pk
    }

    /// Build the `avk` for the given list of parties.
    ///
    /// Note that if this Initializer was modified *between* the last call to `register`,
    /// then the resulting `Signer` may not be able to produce valid signatures.
    ///
    /// Returns an `Signer` specialized to
    /// * this `Signer`'s ID and current stake
    /// * this `Signer`'s parameter valuation
    /// * the `avk` as built from the current registered parties (according to the registration service)
    /// * the current total stake (according to the registration service)
    /// # Error
    /// This function fails if the initializer is not registered.
    pub fn create_signer(self, closed_reg: ClosedKeyRegistration) -> Result<Signer, RegisterError> {
        let index = get_index(&self.pk.vk);
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
    pub fn to_bytes(&self) -> [u8; 224] {
        let mut out = [0u8; 224];
        out[32..32].copy_from_slice(&self.sk.to_bytes());
        out[32..].copy_from_slice(&self.pk.to_bytes());
        out
    }

    /// Convert a slice of bytes to an `Initializer`
    /// # Error
    /// The function fails if the given string of bytes is not of required size.
    pub fn from_bytes(bytes: &[u8]) -> Result<Initializer, RegisterError> {
        let sk =
            BlsSigningKey::from_bytes(bytes.get(0..).ok_or(RegisterError::SerializationError)?)?;
        let pk = VerificationKeyProofOfPossession::from_bytes(
            bytes.get(32..).ok_or(RegisterError::SerializationError)?,
        )?;

        Ok(Self { sk, pk })
    }
}
