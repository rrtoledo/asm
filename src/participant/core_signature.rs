use std::hash::{Hash, Hasher};

use rand_core::{CryptoRng, RngCore};

use serde::{Deserialize, Serialize};

use crate::AsmSignatureError;
use crate::bls_multi_signature::{
    BLS_SIG_SIZE, BLS_VK_SIZE, BlsSignature, BlsSigningKey, BlsVerificationKey,
};

/// BLS Signature on ephemeral keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreSignature {
    /// Transcient vk: g_2^r
    pub vk: BlsVerificationKey,
    /// Signature on message which verifies with vk: H1(msg)^r
    pub sig: BlsSignature,
}

pub const CS_SIZE: usize = BLS_SIG_SIZE + BLS_VK_SIZE;

impl CoreSignature {
    pub fn new<R: RngCore + CryptoRng>(msg: &[u8], rng: &mut R) -> Self {
        let sk = BlsSigningKey::generate(rng);

        let sig = sk.sign(msg);

        let vk = BlsVerificationKey::from(&sk);
        CoreSignature { vk, sig }
    }

    /// Verify a core signature by checking that its msg component corresponds
    /// to a signature on message msg with respect to public key its vk component.
    pub fn verify(&self, sig: &[u8]) -> Result<(), AsmSignatureError> {
        self.sig
            .verify(sig, &self.vk)
            .map_err(|_| AsmSignatureError::SignatureInvalid)
    }

    /// Return the size in bytes of the core signature
    pub fn size() -> usize {
        CS_SIZE
    }

    /// Unsafe function adding a group element to the msg component
    pub(crate) fn add_msg(self, ck: &BlsSignature) -> Self {
        CoreSignature {
            vk: self.vk,
            sig: self.sig.add(&ck),
        }
    }

    /// Unsafe function adding two core signatures together
    pub(crate) fn add_unsafe(self, other: &CoreSignature) -> Self {
        CoreSignature {
            vk: self.vk.add(&other.vk),
            sig: self.sig.add(&other.sig),
        }
    }

    /// Multiply signature with scalar, used for randomization
    pub(crate) fn multiply(self, scalar: &[u8]) -> Self {
        CoreSignature {
            vk: self.vk.mul(scalar),
            sig: self.sig.mul(scalar),
        }
    }

    /// Convert an `CoreSignature` into bytes
    ///
    /// # Layout
    /// * vk as element of G2
    /// * sig as element of G1
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&self.vk.to_bytes());
        output.extend_from_slice(&self.sig.to_bytes());
        output
    }

    /// Extract a batch compatible `SingleSignature` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<CoreSignature, AsmSignatureError> {
        if bytes.len() != BLS_VK_SIZE + BLS_SIG_SIZE {
            return Err(AsmSignatureError::SerializationError);
        }

        let sigma_vk = BlsVerificationKey::from_bytes(
            bytes
                .get(..BLS_VK_SIZE)
                .ok_or(AsmSignatureError::SerializationError)?,
        )?;
        let sigma_msg = BlsSignature::from_bytes(
            bytes
                .get(BLS_VK_SIZE..)
                .ok_or(AsmSignatureError::SerializationError)?,
        )?;

        Ok(CoreSignature {
            vk: sigma_vk,
            sig: sigma_msg,
        })
    }
}

impl Hash for CoreSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut data = Vec::new();
        data.extend_from_slice(&self.to_bytes());
        Hash::hash_slice(&data, state)
    }
}

impl PartialEq for CoreSignature {
    fn eq(&self, other: &Self) -> bool {
        self.vk == other.vk && self.sig == other.sig
    }
}

impl Eq for CoreSignature {}
