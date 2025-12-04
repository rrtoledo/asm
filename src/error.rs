//! Crate specific errors
use blst::BLST_ERROR;

use crate::bls_multi_signature::{
    BlsSignature, BlsVerificationKey, BlsVerificationKeyProofOfPossession,
};

/// Error types for BLS multi signatures.
#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum MultiSignatureError {
    /// Invalid Single signature
    #[error("Invalid single signature")]
    SignatureInvalid(BlsSignature),

    /// Invalid aggregate signature
    #[error("Invalid aggregated signature")]
    AggregateSignatureInvalid,

    /// This error occurs when the the serialization of the raw bytes failed
    #[error("Invalid bytes")]
    SerializationError,

    /// Incorrect proof of possession
    #[error("Key with invalid PoP")]
    KeyInvalid(Box<BlsVerificationKeyProofOfPossession>),

    /// At least one signature in the batch is invalid
    #[error("One signature in the batch is invalid")]
    BatchInvalid,

    /// Single signature is the infinity
    #[error("Single signature is the infinity")]
    SignatureInfinity(BlsSignature),

    /// Verification key is the infinity
    #[error("Verification key is the infinity")]
    VerificationKeyInfinity(Box<BlsVerificationKey>),

    /// Generic Error
    #[error("Generic Multisignature Error")]
    GenericMultisignatureError,
}

/// Errors which can be output by ASM Aggregate signature verification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BatchedAsmAggregateSignatureError {
    /// Not enough aggregates were provided
    #[error("Not enough aggregates were provided for aggregation")]
    NotEnoughAggregates,

    /// Batch verification of STM signatures failed
    #[error("Batch verification of STM signatures failed")]
    BatchInvalid,

    /// This error occurs when the the serialization of the raw bytes failed
    #[error("Invalid bytes")]
    SerializationError,

    /// Generic Error
    #[error("Generic AsmAggregateSignature Error")]
    GenericBatchedAsmAggregateSignatureError,
}

/// Errors which can be output by ASM Aggregate signature verification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AsmAggregateSignatureError {
    /// Not enough signatures were provided
    #[error("Not enough signatures were provided for aggregation")]
    NotEnoughSignatures,

    /// Not enough aggregates were provided
    #[error("Not enough aggregates were provided for aggregation")]
    NotEnoughAggregates,

    /// A party submitted an invalid signature's index
    #[error("A provided signature's index is invalid")]
    SignatureIndexInvalid,

    /// Batch verification of STM signatures failed
    #[error("Batch verification of STM signatures failed")]
    BatchInvalid,

    /// This error occurs when the the serialization of the raw bytes failed
    #[error("Invalid bytes")]
    SerializationError,

    /// Generic Error
    #[error("Generic AsmAggregateSignature Error")]
    GenericAsmAggregateSignatureError,
}

/// Errors which can be output by ASM single signature verification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum AsmSignatureError {
    /// The signer does not have the aggregation key.
    #[error("The signer was not registered, or the registration was not closed.")]
    NotRegistered,

    /// A party submitted an invalid signature
    #[error("A provided signature is invalid")]
    SignatureInvalid,

    /// A party submitted an invalid signature's index
    #[error("A provided signature's index is invalid")]
    SignatureIndexInvalid,

    // This error occurs when the the serialization of the raw bytes failed
    #[error("Invalid bytes")]
    SerializationError,

    /// Generic Error
    #[error("Generic StmSignature Error")]
    GenericAsmSignatureError,
}

/// Errors which can be output by ASM core signature verification.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CoreSignatureError {
    /// A party submitted an invalid signature
    #[error("A provided signature is invalid")]
    SignatureInvalid,

    // This error occurs when the the serialization of the raw bytes failed
    #[error("Invalid bytes")]
    SerializationError,

    /// Generic Error
    #[error("Generic StmSignature Error")]
    GenericCoreSignatureError,
}

/// Errors which can be outputted by key registration.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum RegisterError {
    /// This key has already been registered by a participant
    #[error("This key has already been registered.")]
    KeyRegistered(Box<BlsVerificationKey>),

    /// Verification key is the infinity
    #[error("Verification key is the infinity")]
    VerificationKeyInfinity(Box<BlsVerificationKey>),

    /// Wrong number of membership keys provided
    #[error("Incorrect number of membership keys")]
    IncorrectNumberMembershipKey,

    /// Invalid membership keys provided
    #[error("Incorrect number of membership keys")]
    InvalidMembershipKey,

    /// The supplied key is not valid
    #[error("The verification of correctness of the supplied key is invalid.")]
    KeyInvalid(Box<BlsVerificationKeyProofOfPossession>),

    /// Serialization error
    #[error("Serialization error")]
    SerializationError,

    /// UnregisteredInitializer error
    #[error("Initializer not registered. Cannot participate as a signer.")]
    UnregisteredInitializer,

    /// Revealed Aggregation secret
    #[error("Aggregation secret revealed.")]
    AggregationSecretRevealed,

    /// Generic error
    #[error("Generic registration error.")]
    GenericRegistrationError,
}

impl From<MultiSignatureError> for RegisterError {
    fn from(e: MultiSignatureError) -> Self {
        match e {
            MultiSignatureError::SerializationError => Self::SerializationError,
            MultiSignatureError::KeyInvalid(e) => Self::KeyInvalid(e),
            MultiSignatureError::VerificationKeyInfinity(e) => Self::VerificationKeyInfinity(e),
            _ => unreachable!(),
        }
    }
}

/// If verifying a single signature, the signature should be provided. If verifying a multi-sig,
/// no need to provide the signature
pub(crate) fn blst_err_to_mithril(
    e: BLST_ERROR,
    sig: Option<BlsSignature>,
    key: Option<BlsVerificationKey>,
) -> Result<(), MultiSignatureError> {
    match e {
        BLST_ERROR::BLST_SUCCESS => Ok(()),
        BLST_ERROR::BLST_PK_IS_INFINITY => {
            if let Some(s) = sig {
                return Err(MultiSignatureError::SignatureInfinity(s));
            }
            if let Some(vk) = key {
                return Err(MultiSignatureError::VerificationKeyInfinity(Box::new(vk)));
            }
            Err(MultiSignatureError::SerializationError)
        }
        BLST_ERROR::BLST_VERIFY_FAIL => {
            if let Some(s) = sig {
                Err(MultiSignatureError::SignatureInvalid(s))
            } else {
                Err(MultiSignatureError::AggregateSignatureInvalid)
            }
        }
        _ => Err(MultiSignatureError::SerializationError),
    }
}

impl From<MultiSignatureError> for AsmSignatureError {
    fn from(e: MultiSignatureError) -> Self {
        match e {
            MultiSignatureError::SerializationError => Self::SerializationError,
            MultiSignatureError::SignatureInvalid(e) => Self::SignatureInvalid,
            MultiSignatureError::BatchInvalid => unreachable!(),
            MultiSignatureError::KeyInvalid(_) => unreachable!(),
            MultiSignatureError::AggregateSignatureInvalid => unreachable!(),
            MultiSignatureError::SignatureInfinity(_) => unreachable!(),
            MultiSignatureError::VerificationKeyInfinity(_) => unreachable!(),
            MultiSignatureError::GenericMultisignatureError => {
                AsmSignatureError::GenericAsmSignatureError
            }
        }
    }
}

impl From<AsmSignatureError> for AsmAggregateSignatureError {
    fn from(e: AsmSignatureError) -> Self {
        match e {
            AsmSignatureError::NotRegistered => Self::BatchInvalid,
            AsmSignatureError::SignatureInvalid => Self::BatchInvalid,
            AsmSignatureError::SignatureIndexInvalid => Self::BatchInvalid,
            AsmSignatureError::SerializationError => Self::SerializationError,
            AsmSignatureError::GenericAsmSignatureError => Self::GenericAsmAggregateSignatureError,
        }
    }
}

impl From<CoreSignatureError> for AsmAggregateSignatureError {
    fn from(e: CoreSignatureError) -> Self {
        match e {
            CoreSignatureError::SerializationError => Self::SerializationError,
            _ => Self::GenericAsmAggregateSignatureError,
        }
    }
}

impl From<AsmAggregateSignatureError> for BatchedAsmAggregateSignatureError {
    fn from(e: AsmAggregateSignatureError) -> Self {
        match e {
            AsmAggregateSignatureError::BatchInvalid => Self::BatchInvalid,
            _ => Self::GenericBatchedAsmAggregateSignatureError,
        }
    }
}
