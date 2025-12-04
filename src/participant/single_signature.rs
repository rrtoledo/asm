use std::hash::{Hash, Hasher};

use blake2::digest::{Digest, FixedOutput};

use serde::{Deserialize, Serialize};

use crate::bls_multi_signature::helper::unsafe_helpers::verify_double_pairing;

use crate::{
    AggregateVerificationKey, AsmSignatureError, CoreSignature, Index, VerificationKey, hash_msg,
};

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
        self.basic_verify(pk, &augmented_message)?;
        Ok(())
    }

    /// Verify a single signature by checking that the index is correct and
    /// that the underlying core signature validates.
    pub(crate) fn basic_verify(
        &self,
        pk: &VerificationKey,
        msg: &[u8],
    ) -> Result<(), AsmSignatureError> {
        // Verify signer's index is correct
        let index = Index::from_vk(pk);
        if index != self.signer_index {
            return Err(AsmSignatureError::SignatureIndexInvalid);
        }

        // Verifying that the core signature with membership key verifiees
        if !verify_double_pairing(
            pk,
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
    pub fn from_bytes<D: Clone + Digest + FixedOutput>(
        bytes: &[u8],
    ) -> Result<SingleSignature, AsmSignatureError> {
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
