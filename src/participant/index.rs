use blake2::{Blake2b, Digest};
use digest::consts::U8;
use serde::{Deserialize, Serialize};

use crate::{
    bls_multi_signature::{BlsSignature, BlsVerificationKey, helper::unsafe_helpers::fr_u8},
    error::IndexError,
};

/// Signer index
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Index {
    index: u8,
}

// Size in bytes
pub const INDEX_SIZE: usize = 1;

impl Index {
    // Size of an index, in bytes
    pub fn size() -> usize {
        INDEX_SIZE
    }

    // Size of an index, in bytes
    pub fn max() -> usize {
        u8::MAX as usize
    }

    // Return the index associated with a verification key
    pub fn from_usize(i: usize) -> Index {
        Index { index: i as u8 }
    }

    pub fn to_usize(self) -> usize {
        self.index as usize
    }

    // Return the index associated with a verification key
    pub fn from_vk(vk: &BlsVerificationKey) -> Index {
        let mut hasher = Blake2b::<U8>::new();
        hasher.update(vk.to_bytes());
        let bytes = hasher.finalize().to_vec();
        let index = bytes[0];
        Index { index }
    }

    pub fn to_bytes(self) -> Vec<u8> {
        self.index.to_be_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IndexError> {
        if bytes.len() != Self::size() {
            Err(IndexError::SerializationError)
        } else {
            Ok(Index { index: bytes[0] })
        }
    }

    // Return the byte representation of the index with a domain separator
    // Used for hashing
    pub fn augmented_index(&self) -> Vec<u8> {
        let mut augmented_message = Vec::new();
        augmented_message.extend_from_slice(b"index");
        augmented_message.extend_from_slice(&self.index.to_be_bytes());
        augmented_message
    }

    /// Hash an index to a G1 element
    /// Compute it as the signature H1(b"index" || index)^sk with sk=1
    pub fn hash_to_g1(&self) -> crate::bls_multi_signature::BlsSignature {
        let blst_one = fr_u8(1);
        let sig = blst_one.sign(&self.augmented_index(), &[], &[]);

        BlsSignature(sig)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bytes() {
        let index = Index::from_usize(42);
        let index_bytes = index.to_bytes();
        assert_eq!(index, Index::from_bytes(&index_bytes).unwrap());
    }
}
