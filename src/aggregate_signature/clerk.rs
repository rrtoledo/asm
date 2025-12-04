use crate::{
    AggregateSignature, AggregateVerificationKey, AsmAggregateSignatureError,
    ClosedKeyRegistration, Signer, SingleSignature, aggregate_signature::BatchedAggregateSignature,
    error::BatchedAsmAggregateSignatureError,
};

/// `Clerk` can verify and aggregate `SingleSignature`s and verify `AggregateSignature`s.
/// Clerks can only be generated with the registration closed.
/// This avoids that a Merkle Tree is computed before all parties have registered.
#[derive(Debug, Clone)]
pub struct Clerk {
    pub(crate) closed_reg: ClosedKeyRegistration,
}

impl Clerk {
    /// Create a new `Clerk` from a closed registration instance.
    pub fn new_clerk_from_closed_key_registration(closed_reg: &ClosedKeyRegistration) -> Self {
        Self {
            closed_reg: closed_reg.clone(),
        }
    }
    /// Create a Clerk from a signer.
    pub fn new_clerk_from_signer(signer: &Signer) -> Self {
        let closed_reg = signer
            .get_closed_key_registration()
            .clone()
            .expect("Core signer does not include closed registration. Clerk, and so, the Stm certificate cannot be built without closed registration!")
            ;

        Self { closed_reg }
    }

    /// Aggregate a set of signatures for their corresponding indices.
    ///
    /// This function first deduplicates the repeated signatures, and if there are enough signatures, it collects the merkle tree indexes of unique signatures.
    /// The list of merkle tree indexes is used to create a batch proof, to prove that all signatures are from eligible signers.
    ///
    /// It returns an instance of `AggregateSignature`.
    pub fn aggregate_signatures(
        &self,
        sigs: &[SingleSignature],
        msg: &[u8],
    ) -> Result<AggregateSignature, AsmAggregateSignatureError> {
        let mut extended_signatures = Vec::with_capacity(sigs.len());
        for sig in sigs {
            let vk_option = self.closed_reg.get_vk(sig.signer_index);
            match vk_option {
                Some(vk) => extended_signatures.push((sig.clone(), vk)),
                None => return Err(AsmAggregateSignatureError::SignatureIndexInvalid),
            }
        }

        AggregateSignature::aggregate_signatures(extended_signatures, msg, &self.closed_reg)
    }

    pub fn update_aggregate(
        &self,
        asm: AggregateSignature,
        sigs: &[SingleSignature],
        msg: &[u8],
    ) -> Result<AggregateSignature, AsmAggregateSignatureError> {
        let mut extended_signatures = Vec::with_capacity(sigs.len());
        for sig in sigs {
            let vk_option = self.closed_reg.get_vk(sig.signer_index);
            match vk_option {
                Some(vk) => extended_signatures.push((sig.clone(), vk)),
                None => return Err(AsmAggregateSignatureError::SignatureIndexInvalid),
            }
        }
        AggregateSignature::update_aggregate(&asm, extended_signatures, msg, &self.closed_reg)
    }

    pub fn merge_aggregates(
        &self,
        asms: Vec<AggregateSignature>,
        sigs: &[SingleSignature],
        msg: &[u8],
    ) -> Result<AggregateSignature, AsmAggregateSignatureError> {
        let mut asms_cloned = asms.clone();
        let asm = asms_cloned.pop().unwrap();

        asm.merge_aggregates(asms_cloned, msg, &self.closed_reg)
    }

    pub fn verify_aggregate(
        &self,
        asm: AggregateSignature,
        msg: &[u8],
    ) -> Result<(), AsmAggregateSignatureError> {
        asm.verify(msg, self.closed_reg.aggregate_key)
    }

    pub fn batch_aggregates(
        &self,
        asms: Vec<AggregateSignature>,
        msg: &[u8],
    ) -> Result<BatchedAggregateSignature, BatchedAsmAggregateSignatureError> {
        BatchedAggregateSignature::batch(&asms, msg, &self.closed_reg)
    }

    pub fn verify_batched(
        &self,
        batched: BatchedAggregateSignature,
        msg: &[u8],
    ) -> Result<(), BatchedAsmAggregateSignatureError> {
        batched.verify(msg, &self.closed_reg)
    }

    pub fn batch_verify(
        &self,
        asms: &[AggregateSignature],
        msg: &[u8],
    ) -> Result<(), BatchedAsmAggregateSignatureError> {
        BatchedAggregateSignature::batch_verify(asms, msg, &self.closed_reg)
    }

    /// Compute the `AggregateVerificationKey` related to the used registration.
    pub fn compute_aggregate_verification_key(&self) -> AggregateVerificationKey {
        AggregateVerificationKey::from(&self.closed_reg)
    }
}
