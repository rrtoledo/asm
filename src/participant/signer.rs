use crate::bls_multi_signature::{BlsSignature, BlsSigningKey, BlsVerificationKey};
use crate::{
    AggregateVerificationKey, AsmSignatureError, ClosedKeyRegistration, CoreSignature, Index,
    RegisterError, SingleSignature,
};
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
    registered: Option<(Index, BlsSignature, AggregateVerificationKey)>,
}

impl Signer {
    /// Create a Signer for given input
    pub(crate) fn set_signer(
        sk: BlsSigningKey,
        vk: VerificationKey,
        registry: ClosedKeyRegistration,
    ) -> Result<Signer, RegisterError> {
        let signer_index = Index::from_vk(&vk);

        // Fetching the membership key ck
        let keys_opt = registry.get_keys(signer_index);
        if keys_opt.is_none() {
            return Err(RegisterError::UnregisteredInitializer);
        }

        // Checking that the registered vk is indeed the signer's
        let (vk_registered, ck) = keys_opt.unwrap();
        if vk != vk_registered {
            return Err(RegisterError::UnregisteredInitializer);
        }
        // Verifying ck
        let sk_sig = sk.sign(&signer_index.augmented_index());
        let avk_sig = ck.clone().add(&sk_sig);
        if avk_sig
            .verify(&signer_index.augmented_index(), &registry.aggregate_key.0)
            .is_err()
        {
            return Err(RegisterError::InvalidMembershipKey);
        };

        let registered = Some((signer_index, ck, registry.aggregate_key));

        Ok(Self { sk, vk, registered })
    }

    /// Create a basic signer (no registration data) for given input
    pub(crate) fn set_basic_signer(sk: BlsSigningKey, vk: VerificationKey) -> Signer {
        Self {
            sk,
            vk,
            registered: None,
        }
    }

    /// Create a signature on a message expanded with the aggregate key if the
    /// signer is registered.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<SingleSignature, AsmSignatureError> {
        match self.registered {
            Some((signer_index, ck, avk)) => {
                // Creating the core signature on the message with ephemeral key.
                let expanded_msg = [msg, &avk.0.to_bytes()].concat();
                let sig = self.basic_sign(&expanded_msg, rng);

                // We made the arbitrary choice to add ck here instead of doing it
                // at aggregation which also is possible.
                let sigma = sig.sigma.add_sig(&ck);
                Ok(SingleSignature {
                    sigma,
                    signer_index,
                })
            }
            None => Err(AsmSignatureError::NotRegistered),
        }
    }

    /// A basic signature generated without closed key registration.
    /// The basic signature can be verified by basic verifier.
    pub fn basic_sign<R: RngCore + CryptoRng>(&self, msg: &[u8], rng: &mut R) -> SingleSignature {
        let signer_index = Index::from_vk(&self.vk);

        // Creating a core signature on fresh randomness
        let core_sig = CoreSignature::new(msg, rng);

        // Signing the index with the secret key and combining it with the
        // core signature on the index.
        let sk_sig = self.sk.sign(&signer_index.augmented_index());
        let sigma = core_sig.add_sig(&sk_sig);

        SingleSignature {
            signer_index,
            sigma,
        }
    }

    /// Extract the verification key.
    pub fn get_verification_key(&self) -> VerificationKey {
        self.vk
    }
}
