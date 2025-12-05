//! Key registration functionality.
use std::collections::{HashMap, hash_map::Entry};

use crate::bls_multi_signature::{BlsSignature, BlsVerificationKeyProofOfPossession};
use crate::error::RegisterError;
use crate::{AggregateVerificationKey, Index, VerificationKey};
use serde::{Deserialize, Serialize};

/// Stores a registered party with its public key and the associated stake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredParty {
    pub pk: VerificationKey,
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
        if mks.len() != Index::max() as usize {
            return Err(RegisterError::IncorrectNumberMembershipKey);
        }

        let index = Index::from_vk(&pk.vk);

        if let Entry::Vacant(e) = self.keys.entry(index) {
            pk.verify_proof_of_possesion()?;

            for (i, mk) in mks.iter().enumerate() {
                let res = mk.verify(&Index::from_usize(i).augmented_index(), &pk.vk);
                if i != index.to_usize() && res.is_err() {
                    return Err(RegisterError::InvalidMembershipKey);
                }
                if i == index.to_usize() && res.is_ok() {
                    return Err(RegisterError::AggregationSecretRevealed);
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
        let mut avk: Option<AggregateVerificationKey> = None;
        let mut cks: Vec<Option<BlsSignature>> = (0..Index::max()).map(|_| None).collect();
        let mut registered_parties = Vec::new();

        // Computing avk and the cks
        for (&index, reg) in &self.keys {
            if avk.is_none() {
                avk = Some(AggregateVerificationKey(reg.pk));
            } else {
                avk = Some(AggregateVerificationKey(avk.unwrap().0.add(&reg.pk)));
            }

            for i in 0..(Index::max() as usize) {
                if i != index.to_usize() {
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
            registered_parties.push((index, reg, cks[index.to_usize()].unwrap()));
        }

        if avk.is_some() {
            Ok(ClosedKeyRegistration {
                registered_parties,
                aggregate_key: avk.unwrap(),
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

    pub fn get_vk(&self, index: Index) -> Option<VerificationKey> {
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
    pub fn get_keys(&self, index: Index) -> Option<(VerificationKey, BlsSignature)> {
        for (i, p, ck) in &self.registered_parties {
            if index == *i {
                return Some((p.pk, *ck));
            }
        }
        None
    }
}
