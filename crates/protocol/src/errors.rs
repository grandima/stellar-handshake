use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;
use std::{fmt, io};
use xdr::{DecodeError};
use crate::connection_authentication::AuthenticationError;
use crate::prelude::W;

#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Local and remote sequences do not match")]
    SequenceMismatch,
    #[error("Mac key verification failed")]
    MacKey,
}

#[derive(Debug, Error)]
#[error("Stellar error")]
pub enum StellarError {
    AuthenticationError(#[from] AuthenticationError),
    #[error("Decode error")]
    DecodeError(#[from] W<DecodeError>),
    #[error("IO error: {0}")]
    IOError(#[from] io::Error),
    ConnectionResetByPeer,
    ExpectedMoreMessages,
    Verification(#[from] VerificationError),
}

impl fmt::Display for W<DecodeError> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.0 {
            DecodeError::SuddenEnd { actual_length, expected_length } => {
                write!(f, "The XDR data ends too early. Expected length: {}, actual length: {}.", expected_length, actual_length)
            }
            DecodeError::InvalidEnumDiscriminator { at_position } => {
                write!(f, "Invalid enum discriminator at position {}.", at_position)
            }
            DecodeError::InvalidXdrArchiveLength { at_position } => {
                write!(f, "Invalid length encoding in XDR stream at position {}.", at_position)
            }
            DecodeError::ExceedsMaximumLength { requested_length, allowed_length } => {
                write!(f, "Exceeds Maximum Length requested: {}, allowed: {} .", requested_length,  allowed_length)
            }
        }
    }
}

impl Debug for W<DecodeError> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for W<DecodeError> {}

impl From<DecodeError> for StellarError {
    fn from(value: DecodeError) -> Self {
        Self::DecodeError(W(value))
    }
}

// impl Display for W<StellarSdkError> {
//     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//         match self.0 {
//             StellarSdkError::ExceedsMaximumLength { requested_length, allowed_length } => {
//                 write!(f, "The requested length {} exceeds the maximum allowed length {}", requested_length, allowed_length)
//             },
//             _ => write!(f, "Other error")
//         }
//     }
// }
//
// impl Debug for W<StellarSdkError> {
//     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
//         Display::fmt(self, f)
//     }
// }
//
// impl std::error::Error for W<StellarSdkError> {}
//
// impl From<StellarSdkError> for StellarError {
//     fn from(value: StellarSdkError) -> Self {
//             Self::StellarSdkError(W(value))
//     }
// }