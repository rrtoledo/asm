use std::collections::{BTreeMap, HashMap, HashSet};

use crate::bls_multi_signature::{BlsSignature, BlsVerificationKey};
use crate::key_registration::RegisteredParty;
use crate::{AggregationError, CoreSignature, CoreVerifierError, Index, SingleSignature};

/// Full node verifier including the list of eligible signers and the total stake of the system.
pub struct BasicVerifier {
    /// List of registered parties.
    pub eligible_parties: Vec<RegisteredParty>,
}

impl BasicVerifier {
    /// Setup a basic verifier for given list of signers.
    ///     * Collect the unique signers in a hash set,
    ///     * Calculate the total stake of the eligible signers,
    ///     * Sort the eligible signers.
    pub fn new(public_signers: &[(BlsVerificationKey, Stake)]) -> Self {
        let mut total_stake: Stake = 0;
        let mut unique_parties = HashSet::new();
        for signer in public_signers.iter() {
            let (res, overflow) = total_stake.overflowing_add(signer.1);
            if overflow {
                panic!("Total stake overflow");
            }
            total_stake = res;
            unique_parties.insert(MerkleTreeLeaf(signer.0, signer.1));
        }

        let mut eligible_parties: Vec<_> = unique_parties.into_iter().collect();
        eligible_parties.sort_unstable();
        BasicVerifier {
            eligible_parties,
            total_stake,
        }
    }

    /// Setup a basic verifier for given list of signers.
    ///     * Collect the unique signers in a hash set,
    ///     * Calculate the total stake of the eligible signers,
    ///     * Sort the eligible signers.
    #[deprecated(since = "0.5.0", note = "Use `new` instead")]
    pub fn setup(public_signers: &[(BlsVerificationKey, Stake)]) -> Self {
        Self::new(public_signers)
    }

    /// Preliminary verification that checks whether indices are unique and the quorum is achieved.
    pub(crate) fn preliminary_verify(
        total_stake: &Stake,
        signatures: &[SingleSignatureWithRegisteredParty],
        parameters: &Parameters,
        msg: &[u8],
    ) -> Result<(), CoreVerifierError> {
        let mut nr_indices = 0;
        let mut unique_indices = HashSet::new();

        for sig_reg in signatures {
            sig_reg
                .sig
                .check_indices(parameters, &sig_reg.reg_party.1, msg, total_stake)?;
            for &index in &sig_reg.sig.indexes {
                unique_indices.insert(index);
                nr_indices += 1;
            }
        }

        if nr_indices != unique_indices.len() {
            return Err(CoreVerifierError::IndexNotUnique);
        }
        if (nr_indices as u64) < parameters.k {
            return Err(CoreVerifierError::NoQuorum(nr_indices as u64, parameters.k));
        }

        Ok(())
    }

    /// Core verification
    ///
    /// Verify a list of signatures with respect to given message with given parameters.
    pub fn verify(
        &self,
        signatures: &[SingleSignature],
        parameters: &Parameters,
        msg: &[u8],
    ) -> Result<(), CoreVerifierError> {
        let sig_reg_list = signatures
            .iter()
            .map(|sig| SingleSignatureWithRegisteredParty {
                sig: sig.clone(),
                reg_party: self.eligible_parties[sig.signer_index as usize],
            })
            .collect::<Vec<SingleSignatureWithRegisteredParty>>();

        let unique_sigs = Self::select_valid_signatures_for_k_indices(
            &self.total_stake,
            parameters,
            msg,
            &sig_reg_list,
        )?;

        Self::preliminary_verify(&self.total_stake, &unique_sigs, parameters, msg)?;

        let (sigs, vks) = Self::collect_signatures_verification_keys(&unique_sigs);

        BlsSignature::verify_aggregate(msg.to_vec().as_slice(), &vks, &sigs)?;

        Ok(())
    }
}
