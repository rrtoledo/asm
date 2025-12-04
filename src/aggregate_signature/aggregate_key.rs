use serde::{Deserialize, Serialize};

use crate::{ClosedKeyRegistration, bls_multi_signature::BlsVerificationKey};

/// Stm aggregate key (batch compatible), which contains the merkle tree commitment and the total stake of the system.
/// Batch Compat Merkle tree commitment includes the number of leaves in the tree in order to obtain batch path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct AggregateVerificationKey(pub BlsVerificationKey);

impl From<&ClosedKeyRegistration> for AggregateVerificationKey {
    fn from(reg: &ClosedKeyRegistration) -> Self {
        reg.aggregate_key
    }
}
