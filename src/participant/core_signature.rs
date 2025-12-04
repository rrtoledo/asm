use std::hash::{Hash, Hasher};

use rand_core::{CryptoRng, RngCore};

use serde::{Deserialize, Serialize};

use crate::AsmSignatureError;
use crate::bls_multi_signature::{BlsSignature, BlsSigningKey, BlsVerificationKey};

/// Signature created by a single party who has won the lottery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreSignature {
    /// Commitment to randomness in G2 (hence BlsVerificationKey) g_2^r
    pub rnd: BlsVerificationKey,
    /// Signature on message with randomness as secret key H1(msg)^r
    pub msg: BlsSignature,
}

impl Hash for CoreSignature {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut data = Vec::new();
        data.extend_from_slice(&self.rnd.to_bytes());
        data.extend_from_slice(&self.msg.to_bytes());
        Hash::hash_slice(&data, state)
    }
}

impl PartialEq for CoreSignature {
    fn eq(&self, other: &Self) -> bool {
        self.rnd == other.rnd && self.msg == other.msg
    }
}

impl Eq for CoreSignature {}

impl CoreSignature {
    pub fn new<R: RngCore + CryptoRng>(msg: &[u8], rng: &mut R) -> Self {
        let random_coin = BlsSigningKey::generate(rng);

        let sigma_msg = random_coin.sign(msg);

        let sigma_rnd = BlsVerificationKey::from(&random_coin);
        CoreSignature {
            rnd: sigma_rnd,
            msg: sigma_msg,
        }
    }

    /// Verify an stm signature by checking that the lottery was won, the merkle path is correct,
    /// the indexes are in the desired range and the underlying multi signature validates.
    pub fn verify(&self, msg: &[u8]) -> Result<(), AsmSignatureError> {
        self.msg
            .verify(msg, &self.rnd)
            .map_err(|_| AsmSignatureError::SignatureInvalid)
    }

    pub fn add_msg(self, ck: &BlsSignature) -> Self {
        CoreSignature {
            rnd: self.rnd,
            msg: self.msg.add(&ck),
        }
    }

    pub fn add_unsafe(self, other: &CoreSignature) -> Self {
        CoreSignature {
            rnd: self.rnd.add(&other.rnd),
            msg: self.msg.add(&other.msg),
        }
    }

    pub fn multiply(self, scalar: &[u8]) -> Self {
        CoreSignature {
            rnd: self.rnd.mul(scalar),
            msg: self.msg.mul(scalar),
        }
    }

    /// Convert an `CoreSignature` into bytes
    ///
    /// # Layout
    /// * Signer Index
    /// * Public Key
    /// * Signature:
    /// ** rnd as element of G2
    /// ** msg as element of G1
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&self.rnd.to_bytes());
        output.extend_from_slice(&self.msg.to_bytes());
        output
    }

    /// Extract a batch compatible `SingleSignature` from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<CoreSignature, AsmSignatureError> {
        let sigma_rnd = BlsVerificationKey::from_bytes(
            bytes
                .get(..96)
                .ok_or(AsmSignatureError::SerializationError)?,
        )?;
        let sigma_msg = BlsSignature::from_bytes(
            bytes
                .get(96..)
                .ok_or(AsmSignatureError::SerializationError)?,
        )?;

        Ok(CoreSignature {
            rnd: sigma_rnd,
            msg: sigma_msg,
        })
    }
}
