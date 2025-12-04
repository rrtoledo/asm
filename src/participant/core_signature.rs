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
    pub fn verify(&self, msg: &[u8]) -> Result<(), AsmSignatureError> {
        self.sig
            .verify(msg, &self.vk)
            .map_err(|_| AsmSignatureError::SignatureInvalid)
    }

    /// Return the size in bytes of the core signature
    pub fn size() -> usize {
        CS_SIZE
    }

    /// Unsafe function adding a group element to the msg component
    pub(crate) fn add_sig(self, ck: &BlsSignature) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls_multi_signature::helper::unsafe_helpers::{p1_affine_to_sig, p1_mul, sig_to_p1};

    use rand_chacha::ChaCha20Rng;
    use rand_core::{RngCore, SeedableRng};

    #[test]
    fn test_bytes() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let msg = rng.next_u32().to_le_bytes();
        let cs = CoreSignature::new(&msg, rng);
        let cs_bytes = cs.to_bytes();
        assert_eq!(cs, CoreSignature::from_bytes(&cs_bytes).unwrap());
    }

    #[test]
    fn test_verify_positive() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let msg = rng.next_u32().to_le_bytes();
        let cs = CoreSignature::new(&msg, rng);
        let valid = cs.verify(&msg);
        assert!(valid.is_ok());
    }

    #[test]
    fn test_verify_negative() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let msg = rng.next_u32().to_le_bytes();
        let cs = CoreSignature::new(&msg, rng);
        let valid = cs.verify(&rng.next_u32().to_le_bytes());
        assert!(valid.is_err());
    }

    #[test]
    fn test_add_sig() {
        let mut seed = [0; 32];
        seed[0] = 42;
        let rng = &mut ChaCha20Rng::from_seed(seed);

        let msg = rng.next_u32().to_le_bytes();
        let cs = CoreSignature::new(&msg, rng);
        let cs_updated = cs.clone().add_sig(&cs.sig);
        assert_eq!(cs_updated.vk, cs.vk);
        assert_ne!(cs_updated.sig, cs.sig);
        let p1_pow_2 = p1_mul(&sig_to_p1(&cs.sig.0), &[2u8, 0u8], 16);
        assert_eq!(cs_updated.sig.0, p1_affine_to_sig(&p1_pow_2));
    }
}
