mod aggregate_signature;
mod bls_multi_signature;
mod error;
mod participant;
pub(crate) mod utils;

pub use aggregate_signature::{
    AggregateSignature, AggregateVerificationKey, BatchedAggregateSignature,
};
pub use error::{AsmAggregateSignatureError, AsmSignatureError, RegisterError};
pub use participant::{
    CS_SIZE, ClosedKeyRegistration, CoreSignature, INDEX_SIZE, Index, Initializer, KeyRegistration,
    RegisteredParty, Signer, SingleSignature, VerificationKey, VerificationKeyProofOfPossession,
};

#[cfg(feature = "benchmark-internals")]
pub use bls_multi_signature::{
    BlsProofOfPossession, BlsSignature, BlsSigningKey, BlsVerificationKey,
    BlsVerificationKeyProofOfPossession,
};
