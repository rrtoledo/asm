use crate::bls_multi_signature::{BlsSigningKey, BlsVerificationKey};
use crate::key_registration::ClosedKeyRegistration;
use crate::{AsmSignatureError, CoreSignature, SingleSignature, get_index, augmented_index};
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

    /// This function produces a signature following the description of Section 2.4.
    /// Once the signature is produced, this function checks whether any index in `[0,..,self.params.m]`
    /// wins the lottery by evaluating the dense mapping.
    /// It records all the winning indexes in `Self.indexes`.
    /// If it wins at least one lottery, it stores the signer's merkle tree index. The proof of membership
    /// will be handled by the aggregator.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<SingleSignature, AsmSignatureError> {
        match self.closed_reg.as_ref() {
            Some(registry) => {
                let expanded_msg = [msg, &registry.aggregate_key.0.to_bytes()].concat();
                let signature = self.basic_sign(&expanded_msg, rng);
                Ok(signature)
            }
            None => Err(AsmSignatureError::NotRegistered),
        }
    }

    /// Extract the verification key.
    pub fn get_verification_key(&self) -> VerificationKey {
        self.vk
    }

    /// A basic signature generated without closed key registration.
    /// The basic signature can be verified by basic verifier.
    /// TODO MAKE SIGNATURE AGGREGATE READY
    pub fn basic_sign<R: RngCore + CryptoRng>(&self, msg: &[u8], rng: &mut R) -> SingleSignature {
        let signer_index = get_index(&self.vk);
        let closed_reg = self.closed_reg.as_ref().expect("Closed registration not found! Cannot produce SingleSignatures. Use core_sign to produce core signatures (not valid for an AsmCertificate).");
        let (vk, ck) = closed_reg.get_keys(signer_index).expect("Signer not registered! Cannot produce SingleSignatures. Use core_sign to produce core signatures (not valid for an AsmCertificate).");
        assert!(vk == self.vk);

        // Creating a core signature on fresh randomness
        let core_sig = CoreSignature::new(msg, rng);

        // Signing the index with the secret key and combining them all
        // together with ck for aggregation
        let sk_sig = self.sk.sign(&augmented_index(signer_index));
        let sigma = core_sig.add_msg(&sk_sig).add_msg(&ck);

        // Adding membership key

        SingleSignature {
            signer_index,
            sigma,
        }
    }

    /// Get closed key registration
    pub(crate) fn get_closed_key_registration(&self) -> Option<ClosedKeyRegistration> {
        self.closed_reg.clone()
    }
}
