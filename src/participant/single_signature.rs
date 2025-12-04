use std::hash::{Hash, Hasher};

use blake2::digest::{Digest, FixedOutput};

use serde::{Deserialize, Serialize};

use crate::bls_multi_signature::{
    BlsSignature, BlsVerificationKey, helper::unsafe_helpers::verify_double_pairing,
};

use crate::{
    AggregateVerificationKey, AsmSignatureError, CoreSignature, Index, VerificationKey, get_index,
    hash_index, hash_msg,
};

/// Signature created by a single party who has won the lottery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SingleSignature {
    /// The signature.
    pub sigma: CoreSignature,
    /// Signer's index
    pub signer_index: Index,
}

impl SingleSignature {
    /// Verify an stm signature by checking that the lottery was won, the merkle path is correct,
    /// the indexes are in the desired range and the underlying multi signature validates.
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

    /// Convert an `SingleSignature` into bytes
    ///
    /// # Layout
    /// * Signer Index
    /// * Public Key
    /// * Signature:
    /// ** rnd as element of G2
    /// ** msg as element of G1
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&[self.signer_index]);
        output.extend_from_slice(&self.sigma.rnd.to_bytes());
        output.extend_from_slice(&self.sigma.msg.to_bytes());
        output
    }

    /// Extract a batch compatible `SingleSignature` from a byte slice.
    pub fn from_bytes<D: Clone + Digest + FixedOutput>(
        bytes: &[u8],
    ) -> Result<SingleSignature, AsmSignatureError> {
        let signer_index = Index::from_be_bytes([bytes[0]]);

        let sigma_rnd = BlsVerificationKey::from_bytes(
            bytes
                .get(1..1 + 2 * 96)
                .ok_or(AsmSignatureError::SerializationError)?,
        )?;
        let sigma_msg = BlsSignature::from_bytes(
            bytes
                .get(1 + 96..)
                .ok_or(AsmSignatureError::SerializationError)?,
        )?;

        Ok(SingleSignature {
            signer_index,
            sigma: CoreSignature {
                rnd: sigma_rnd,
                msg: sigma_msg,
            },
        })
    }

    /// Verify a basic signature by checking that the underlying multi signature validates.
    pub(crate) fn basic_verify(
        &self,
        pk: &VerificationKey,
        msg: &[u8],
    ) -> Result<(), AsmSignatureError> {
        // Verify signer's index is correct
        let index = get_index(pk);
        if index != self.signer_index {
            return Err(AsmSignatureError::SignatureIndexInvalid);
        }

        if !verify_double_pairing(
            pk,
            &self.sigma.msg.0,
            &self.sigma.rnd,
            &hash_index(index).0,
            &hash_msg(msg).0,
        ) {
            return Err(AsmSignatureError::SignatureInvalid);
        }

        Ok(())
    }
}

impl Hash for SingleSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut data = Vec::new();
        data.extend_from_slice(&[self.signer_index]);
        data.extend_from_slice(&self.sigma.rnd.to_bytes());
        data.extend_from_slice(&self.sigma.msg.to_bytes());
        Hash::hash_slice(&data, state)
    }
}

impl PartialEq for SingleSignature {
    fn eq(&self, other: &Self) -> bool {
        self.sigma.rnd == other.sigma.rnd
            && self.sigma.msg == other.sigma.msg
            && self.signer_index == other.signer_index
    }
}

impl Eq for SingleSignature {}
