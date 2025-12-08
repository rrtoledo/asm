//! Key registration functionality.
use std::collections::{HashMap, hash_map::Entry};
use std::default;

use crate::bls_multi_signature::{BlsSignature, BlsVerificationKeyProofOfPossession};
use crate::error::RegisterError;
use crate::{AggregateVerificationKey, Index, VerificationKey};
use serde::{Deserialize, Serialize};

/// Stores a registered party with its public key and the associated stake.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisteredParty {
    pub vk: VerificationKey,
    pub mks: Option<Vec<(Index, BlsSignature)>>,
}

/// Struct that collects public keys and stakes of parties.
/// Each participant (both the signers and the clerks) need to run their own instance of the key registration.
// todo: replace with KeyReg
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KeyRegistration {
    keys: HashMap<Index, RegisteredParty>,
    is_closed: bool,
}

impl KeyRegistration {
    /// Initialize an empty `KeyRegistration`.
    pub fn init() -> Self {
        Self {
            keys: HashMap::default(),
            is_closed: false,
        }
    }

    /// Verify and register a public key and stake for a particular party.
    /// # Error
    /// The function fails when the proof of possession is invalid or when the key is already registered.
    pub fn pre_register(
        &mut self,
        pk: BlsVerificationKeyProofOfPossession,
    ) -> Result<(), RegisterError> {
        if !self.is_closed {
            let index = Index::from_vk(&pk.vk);

            if let Entry::Vacant(e) = self.keys.entry(index) {
                pk.verify_proof_of_possesion()?;

                e.insert(RegisteredParty {
                    vk: pk.vk,
                    mks: None,
                });

                return Ok(());
            }
            return Err(RegisterError::KeyRegistered(Box::new(pk.vk)));
        }
        Err(RegisterError::ClosedPreRegistration)
    }

    pub fn close_preregistration(&mut self) -> Vec<Index> {
        self.is_closed = true;
        let mut keys = self.keys.keys().cloned().collect::<Vec<Index>>();
        keys.sort();
        keys
    }

    pub fn register(
        &mut self,
        vk: VerificationKey,
        mks: &[(Index, BlsSignature)],
    ) -> Result<(), RegisterError> {
        if !self.is_closed {
            return Err(RegisterError::OpenedPreRegistration);
        }

        if mks.len() != self.keys.len() as usize {
            return Err(RegisterError::IncorrectNumberMembershipKey);
        }

        if !mks.iter().all(|(i, _sig)| self.keys.contains_key(i)) {
            return Err(RegisterError::InvalidMembershipKey);
        }

        let index = Index::from_vk(&vk);

        if let Entry::Occupied(mut e) = self.keys.entry(index) {
            let registered_party = e.get_mut();
            if registered_party.vk == vk && registered_party.mks.is_none() {
                for (i, mk) in mks {
                    let res = mk.verify(&i.augmented_index(), &vk);
                    if *i != index && res.is_err() {
                        return Err(RegisterError::InvalidMembershipKey);
                    }
                    if *i == index && res.is_ok() {
                        return Err(RegisterError::AggregationSecretRevealed);
                    }
                }

                e.get_mut().mks = Some(mks.to_vec());

                return Ok(());
            }
        }
        Err(RegisterError::KeyRegistered(Box::new(vk)))
    }

    /// Finalize the key registration.
    /// This function disables `KeyReg::register`, consumes the instance of `self`, and returns a `ClosedKeyRegistration`.
    pub fn close(self) -> Result<ClosedKeyRegistration, RegisterError> {
        let mut avk: Option<AggregateVerificationKey> = None;
        let mut cks = HashMap::<Index, BlsSignature>::default();
        let mut registered_parties = Vec::new();

        // Filter the unregistered keys
        let mut to_remove = Vec::new();

        let filtered = self
            .keys
            .iter()
            .filter_map(|(&i, r)| {
                if r.mks.is_none() {
                    to_remove.push(i);
                    return None;
                }
                Some((i, r.clone()))
            })
            .collect::<Vec<(Index, RegisteredParty)>>();

        // Computing avk and the cks
        for (index, reg) in &filtered {
            if avk.is_none() {
                avk = Some(AggregateVerificationKey(reg.vk));
            } else {
                avk = Some(AggregateVerificationKey(avk.unwrap().0.add(&reg.vk)));
            }

            let mks = reg.mks.clone().unwrap();
            for (i, mk) in mks {
                if i != *index && !to_remove.contains(&i) {
                    if !cks.contains_key(&i) {
                        cks.insert(i, mk);
                    } else {
                        let new_ck = cks.get_mut(&i).unwrap().add(&mk);
                        cks.insert(i, new_ck);
                    }
                }
            }
        }

        // Collecting available parties
        for (index, reg) in filtered {
            let ck = cks.get(&index).unwrap().clone();
            registered_parties.push((index, reg, ck));
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
                return Some(p.vk);
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
                return Some((p.vk, *ck));
            }
        }
        None
    }
}
