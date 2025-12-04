use crate::bls_multi_signature::{BlsSigningKey, BlsVerificationKey};
use crate::{AsmSignatureError, ClosedKeyRegistration, CoreSignature, Index, SingleSignature};
use rand_core::{CryptoRng, RngCore};

/// Wrapper of the MultiSignature Verification key
pub type VerificationKey = BlsVerificationKey;

/// Participant in the protocol can sign messages.
/// * If the signer has `closed_reg`, then it can generate Stm certificate.
///     * This kind of signer can only be generated out of an `Initializer` and a `ClosedKeyRegistration`.
///     * This ensures that a `MerkleTree` root is not computed before all participants have registered.
/// * If the signer does not have `closed_reg`, then it is a core signer.
///     * This kind of signer cannot participate certificate generation.
///     * Signature generated can be verified by a full node verifier (core verifier).
#[derive(Debug, Clone)]
pub struct Signer {
    sk: BlsSigningKey,
    vk: VerificationKey,
    closed_reg: Option<ClosedKeyRegistration>,
}

impl Signer {
    /// Create a Signer for given input
    pub(crate) fn set_signer(
        sk: BlsSigningKey,
        vk: VerificationKey,
        closed_reg: ClosedKeyRegistration,
    ) -> Signer {
        Self {
            sk,
            vk,
            closed_reg: Some(closed_reg),
        }
    }

    /// Create a basic signer (no registration data) for given input
    pub(crate) fn set_basic_signer(sk: BlsSigningKey, vk: VerificationKey) -> Signer {
        Self {
            sk,
            vk,
            closed_reg: None,
        }
    }

    /// Create a signature on a message expanded with the aggregate key if the
    /// signer is registered.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<SingleSignature, AsmSignatureError> {
        match self.closed_reg.as_ref() {
            Some(registry) => {
                let expanded_msg = [msg, &registry.aggregate_key.0.to_bytes()].concat();
                self.basic_sign(&expanded_msg, rng)
            }
            None => Err(AsmSignatureError::NotRegistered),
        }
    }

    /// A basic signature generated without closed key registration.
    /// The basic signature can be verified by basic verifier.
    pub fn basic_sign<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<SingleSignature, AsmSignatureError> {
        let signer_index = Index::from_vk(&self.vk);

        if let Some(registry) = &self.closed_reg {
            let keys_opt = registry.get_keys(signer_index);
            if keys_opt.is_none() {
                return Err(AsmSignatureError::NotRegistered);
            }

            let (vk, ck) = keys_opt.unwrap();
            if vk != self.vk {
                return Err(AsmSignatureError::NotRegistered);
            }

            // Creating a core signature on fresh randomness
            let core_sig = CoreSignature::new(msg, rng);

            // Signing the index with the secret key and combining them all
            // together with the membership key ck for aggregation
            let sk_sig = self.sk.sign(&signer_index.augmented_index());
            let sigma = core_sig.add_msg(&sk_sig).add_msg(&ck);

            return Ok(SingleSignature {
                signer_index,
                sigma,
            });
        }
        Err(AsmSignatureError::NotRegistered)
    }

    /// Extract the verification key.
    pub fn get_verification_key(&self) -> VerificationKey {
        self.vk
    }

    /// Get closed key registration
    pub(crate) fn get_closed_key_registration(&self) -> Option<ClosedKeyRegistration> {
        self.closed_reg.clone()
    }
}
