//! Key registration functionality.
use std::collections::{HashMap, hash_map::Entry};

use crate::bls_multi_signature::{
    BlsSignature, BlsVerificationKey, BlsVerificationKeyProofOfPossession,
};
use crate::error::RegisterError;
use crate::{AggregateVerificationKey, Index, get_index};
use serde::{Deserialize, Serialize};

/// Stores a registered party with its public key and the associated stake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredParty {
    pub pk: BlsVerificationKey,
    pub mks: Vec<BlsSignature>,
}

/// Struct that collects public keys and stakes of parties.
/// Each participant (both the signers and the clerks) need to run their own instance of the key registration.
// todo: replace with KeyReg
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyRegistration {
    keys: HashMap<Index, RegisteredParty>,
}

impl KeyRegistration {
    /// Initialize an empty `KeyRegistration`.
    pub fn init() -> Self {
        Self::default()
    }

    /// Verify and register a public key and stake for a particular party.
    /// # Error
    /// The function fails when the proof of possession is invalid or when the key is already registered.
    pub fn register(
        &mut self,
        pk: BlsVerificationKeyProofOfPossession,
        mks: &[BlsSignature],
    ) -> Result<(), RegisterError> {
        if mks.len() != Index::MAX as usize {
            return Err(RegisterError::IncorrectNumberMembershipKey);
        }

        let index = get_index(&pk.vk);

        if let Entry::Vacant(e) = self.keys.entry(index) {
            pk.verify_proof_of_possesion()?;

            for (i, mk) in mks.iter().enumerate() {
                if i != index as usize {
                    if mk.verify(&i.to_be_bytes(), &pk.vk).is_err() {
                        return Err(RegisterError::InvalidMembershipKey);
                    }
                } else {
                    if mk.verify(&i.to_be_bytes(), &pk.vk).is_ok() {
                        return Err(RegisterError::AggregationSecretRevealed);
                    }
                }
            }

            e.insert(RegisteredParty {
                pk: pk.vk,
                mks: mks.to_vec(),
            });

            return Ok(());
        }
        Err(RegisterError::KeyRegistered(Box::new(pk.vk)))
    }

    /// Finalize the key registration.
    /// This function disables `KeyReg::register`, consumes the instance of `self`, and returns a `ClosedKeyRegistration`.
    pub fn close(self) -> Result<ClosedKeyRegistration, RegisterError> {
        let mut avk: Option<BlsVerificationKey> = None;
        let mut cks: Vec<Option<BlsSignature>> = (0..Index::MAX).map(|_| None).collect();
        let mut registered_parties = Vec::new();

        // Computing avk and the cks
        for (&index, reg) in &self.keys {
            if avk.is_none() {
                avk = Some(reg.pk);
            } else {
                avk = Some(BlsVerificationKey::add(&avk.unwrap(), &reg.pk));
            }

            for i in 0..(Index::MAX as usize) {
                if i != index as usize {
                    if cks[i].is_none() {
                        cks[i] = Some(reg.mks[i]);
                    } else {
                        cks[i] = Some(BlsSignature::add(&cks[i].unwrap(), &reg.mks[i]));
                    }
                }
            }
        }

        // Collecting available parties
        for (index, reg) in self.keys {
            registered_parties.push((index, reg, cks[index as usize].unwrap()));
        }

        if avk.is_some() {
            Ok(ClosedKeyRegistration {
                registered_parties,
                aggregate_key: AggregateVerificationKey(avk.unwrap()),
            })
        } else {
            Err(RegisterError::GenericRegistrationError)
        }
    }
}

/// Structure generated out of a closed registration containing the registered parties, total stake, and the merkle tree.
/// One can only get a global `avk` out of a closed key registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedKeyRegistration {
    /// Aggregate verification keys
    pub aggregate_key: AggregateVerificationKey,
    /// List of registered parties, with their indices and membership signature
    pub registered_parties: Vec<(Index, RegisteredParty, BlsSignature)>,
}

impl ClosedKeyRegistration {
    pub fn is_registered(&self, index: Index) -> bool {
        for (i, _p, _ck) in &self.registered_parties {
            if index == *i {
                return true;
            }
        }
        false
    }

    pub fn get_vk(&self, index: Index) -> Option<BlsVerificationKey> {
        for (i, p, _ck) in &self.registered_parties {
            if index == *i {
                return Some(p.pk);
            }
        }
        None
    }

    pub fn get_ck(&self, index: Index) -> Option<BlsSignature> {
        for (i, _p, ck) in &self.registered_parties {
            if index == *i {
                return Some(*ck);
            }
        }
        None
    }
    pub fn get_keys(&self, index: Index) -> Option<(BlsVerificationKey, BlsSignature)> {
        for (i, p, ck) in &self.registered_parties {
            if index == *i {
                return Some((p.pk, *ck));
            }
        }
        None
    }
}

// #[cfg(test)]
// mod tests {
//     use blake2::{Blake2b, digest::consts::U32};
//     use proptest::{collection::vec, prelude::*};
//     use rand_chacha::ChaCha20Rng;
//     use rand_core::SeedableRng;

//     use crate::bls_multi_signature::BlsSigningKey;

//     use super::*;

//     proptest! {
//         #[test]
//         fn test_keyreg(stake in vec(1..1u64 << 60, 2..=10),
//                        nkeys in 2..10_usize,
//                        fake_it in 0..4usize,
//                        seed in any::<[u8;32]>()) {
//             let mut rng = ChaCha20Rng::from_seed(seed);
//             let mut kr = KeyRegistration::init();

//             let gen_keys = (1..nkeys).map(|_| {
//                 let sk = BlsSigningKey::generate(&mut rng);
//                 BlsVerificationKeyProofOfPossession::from(&sk)
//             }).collect::<Vec<_>>();

//             let fake_key = {
//                 let sk = BlsSigningKey::generate(&mut rng);
//                 BlsVerificationKeyProofOfPossession::from(&sk)
//             };

//             // Record successful registrations
//             let mut keys = HashMap::new();

//             for (i, &stake) in stake.iter().enumerate() {
//                 let mut pk = gen_keys[i % gen_keys.len()];

//                 if fake_it == 0 {
//                     pk.pop = fake_key.pop;
//                 }

//                 let reg = kr.register(stake, pk);
//                 match reg {
//                     Ok(_) => {
//                         assert!(keys.insert(pk.vk, stake).is_none());
//                     },
//                     Err(RegisterError::KeyRegistered(pk1)) => {
//                         assert!(pk1.as_ref() == &pk.vk);
//                         assert!(keys.contains_key(&pk.vk));
//                     }
//                     Err(RegisterError::KeyInvalid(a)) => {
//                         assert_eq!(fake_it, 0);
//                         assert!(a.verify_proof_of_possesion().is_err());
//                     }
//                     Err(RegisterError::SerializationError) => unreachable!(),
//                     _ => unreachable!(),
//                 }
//             }

//             if !kr.keys.is_empty() {
//                 let closed = kr.close::<Blake2b<U32>>();
//                 let retrieved_keys = closed.reg_parties.iter().map(|r| (r.0, r.1)).collect::<HashMap<_,_>>();
//                 assert!(retrieved_keys == keys);
//             }
//         }
//     }
// }
