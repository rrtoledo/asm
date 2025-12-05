use std::{cmp::Ordering, iter::Sum};

use blake2::{Blake2b, Digest};
use blst::{
    blst_p1, blst_p2,
    min_sig::{AggregateSignature, PublicKey as BlstVk, Signature as BlstSig},
    p1_affines, p2_affines,
};
use digest::consts::U16;

use crate::bls_multi_signature::{
    BlsVerificationKey,
    helper::unsafe_helpers::{
        p1_add, p1_affine_to_sig, p1_mul, p2_affine_to_vk, sig_to_p1, vk_from_p2_affine,
    },
};
use crate::error::{MultiSignatureError, blst_err_to_mithril};

/// MultiSig signature, which is a wrapper over the `BlstSig` type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlsSignature(pub BlstSig);
pub const BLS_SIG_SIZE: usize = 48;

impl BlsSignature {
    /// Verify a signature against a verification key.
    pub fn verify(&self, msg: &[u8], mvk: &BlsVerificationKey) -> Result<(), MultiSignatureError> {
        blst_err_to_mithril(
            self.0.validate(true).map_or_else(
                |e| e,
                |_| {
                    self.0
                        .verify(false, msg, &[], &[], &mvk.to_blst_verification_key(), false)
                },
            ),
            Some(*self),
            None,
        )
    }

    pub fn size() -> usize {
        BLS_SIG_SIZE
    }

    /// Convert an `Signature` to its compressed byte representation.
    pub fn to_bytes(self) -> [u8; BLS_SIG_SIZE] {
        self.0.to_bytes()
    }

    /// Convert a string of bytes into a `MspSig`.
    ///
    /// # Error
    /// Returns an error if the byte string does not represent a point in the curve.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MultiSignatureError> {
        let bytes = bytes
            .get(..BLS_SIG_SIZE)
            .ok_or(MultiSignatureError::SerializationError)?;
        match BlstSig::sig_validate(bytes, true) {
            Ok(sig) => Ok(Self(sig)),
            Err(e) => Err(blst_err_to_mithril(e, None, None)
                .expect_err("If deserialization is not successful, blst returns and error different to SUCCESS."))
        }
    }

    /// Compare two signatures. Used for PartialOrd impl, used to rank signatures. The comparison
    /// function can be anything, as long as it is consistent across different nodes.
    fn compare_signatures(&self, other: &Self) -> Ordering {
        let self_bytes = self.to_bytes();
        let other_bytes = other.to_bytes();
        let mut result = Ordering::Equal;

        for (i, j) in self_bytes.iter().zip(other_bytes.iter()) {
            result = i.cmp(j);
            if result != Ordering::Equal {
                return result;
            }
        }
        result
    }

    pub fn add(&self, other: &BlsSignature) -> BlsSignature {
        let p = sig_to_p1(&self.0);
        let q = sig_to_p1(&other.0);

        BlsSignature(p1_affine_to_sig(&p1_add(&p, &q)))
    }

    pub fn mul(&self, scalar: &[u8]) -> BlsSignature {
        let p = sig_to_p1(&self.0);

        BlsSignature(p1_affine_to_sig(&p1_mul(&p, scalar, 8 * scalar.len())))
    }

    /// Aggregate a slice of Signatures by multiplying them together
    pub fn aggregate_unsafe(sigs: &[BlsSignature]) -> BlsSignature {
        if sigs.len() < 2 {
            return sigs[0];
        }

        let mut signatures: Vec<blst_p1> = Vec::with_capacity(sigs.len());
        for sig in sigs.iter() {
            signatures.push(sig_to_p1(&sig.0));
        }

        let init = signatures.pop().unwrap();
        let res = signatures.iter().fold(init, |acc, &sig| p1_add(&acc, &sig));

        let aggr_sig: BlstSig = p1_affine_to_sig(&res);

        BlsSignature(aggr_sig)
    }

    /// Aggregate a slice of verification keys and Signatures by first hashing the
    /// signatures into random scalars, and multiplying the signature and verification
    /// key with the resulting value. This follows the steps defined in Figure 6,
    /// `Aggregate` step.
    pub fn aggregate(
        vks: &[BlsVerificationKey],
        sigs: &[BlsSignature],
    ) -> Result<(BlsVerificationKey, BlsSignature), MultiSignatureError> {
        if vks.len() != sigs.len() || vks.is_empty() {
            return Err(MultiSignatureError::AggregateSignatureInvalid);
        }

        if vks.len() < 2 {
            return Ok((vks[0], sigs[0]));
        }

        let mut hashed_sigs = Blake2b::<U16>::new();
        for sig in sigs {
            hashed_sigs.update(sig.to_bytes());
        }

        // First we generate the scalars
        let mut scalars = Vec::with_capacity(vks.len() * 128);
        let mut signatures = Vec::with_capacity(vks.len());
        for (index, sig) in sigs.iter().enumerate() {
            let mut hasher = hashed_sigs.clone();
            hasher.update(index.to_be_bytes());
            signatures.push(sig.0);
            scalars.extend_from_slice(hasher.finalize().as_slice());
        }

        let transmuted_vks: Vec<blst_p2> = vks.iter().map(vk_from_p2_affine).collect();
        let transmuted_sigs: Vec<blst_p1> = signatures.iter().map(sig_to_p1).collect();

        let grouped_vks = p2_affines::from(transmuted_vks.as_slice());
        let grouped_sigs = p1_affines::from(transmuted_sigs.as_slice());

        let aggr_vk: BlstVk = p2_affine_to_vk(&grouped_vks.mult(&scalars, 128));
        let aggr_sig: BlstSig = p1_affine_to_sig(&grouped_sigs.mult(&scalars, 128));

        Ok((BlsVerificationKey(aggr_vk), BlsSignature(aggr_sig)))
    }

    /// Verify a set of signatures with their corresponding verification keys using the
    /// aggregation mechanism of Figure 6.
    pub fn verify_aggregate(
        msg: &[u8],
        vks: &[BlsVerificationKey],
        sigs: &[BlsSignature],
    ) -> Result<(), MultiSignatureError> {
        let (aggr_vk, aggr_sig) = Self::aggregate(vks, sigs)?;

        blst_err_to_mithril(
            aggr_sig.0.verify(
                false,
                msg,
                &[],
                &[],
                &aggr_vk.to_blst_verification_key(),
                false,
            ),
            Some(aggr_sig),
            None,
        )
    }

    /// Batch verify several sets of signatures with their corresponding verification keys.
    pub fn batch_verify_aggregates(
        msgs: &[Vec<u8>],
        vks: &[BlsVerificationKey],
        sigs: &[BlsSignature],
    ) -> Result<(), MultiSignatureError> {
        let batched_sig: BlstSig = match AggregateSignature::aggregate(
            &(sigs.iter().map(|sig| &sig.0).collect::<Vec<&BlstSig>>()),
            false,
        ) {
            Ok(sig) => BlstSig::from_aggregate(&sig),
            Err(e) => return blst_err_to_mithril(e, None, None),
        };

        let p2_vks: Vec<BlstVk> = vks.iter().map(|vk| vk.to_blst_verification_key()).collect();
        let p2_vks_ref: Vec<&BlstVk> = p2_vks.iter().collect();
        let slice_msgs = msgs
            .iter()
            .map(|msg| msg.as_slice())
            .collect::<Vec<&[u8]>>();

        blst_err_to_mithril(
            batched_sig.aggregate_verify(false, &slice_msgs, &[], &p2_vks_ref, false),
            None,
            None,
        )
        .map_err(|_| MultiSignatureError::BatchInvalid)
    }
}

impl<'a> Sum<&'a Self> for BlsSignature {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Self>,
    {
        let signatures: Vec<&BlstSig> = iter.map(|x| &x.0).collect();
        assert!(!signatures.is_empty(), "One cannot add an empty vector");
        let aggregate = AggregateSignature::aggregate(&signatures, false)
            .expect("An MspSig is always a valid signature. This function only fails if signatures is empty or if the signatures are invalid, none of which can happen.")
            .to_signature();

        Self(aggregate)
    }
}

impl PartialOrd for BlsSignature {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(std::cmp::Ord::cmp(self, other))
    }
}

impl Ord for BlsSignature {
    fn cmp(&self, other: &Self) -> Ordering {
        self.compare_signatures(other)
    }
}
