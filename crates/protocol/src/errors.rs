use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;
use std::{fmt, io};
use xdr::{DecodeError, StellarSdkError};
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
    #[error("Sdk error")]
    StellarSdkError(#[from] W<StellarSdkError>),
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
            DecodeError::TypeEndsTooEarly { remaining_no_of_bytes } => {
                write!(f, "The binary data is longer than expected. Remaining bytes: {}.", remaining_no_of_bytes)
            }
            DecodeError::InvalidBoolean { found_integer, at_position } => {
                write!(f, "Invalid boolean at position {}. Found value: {}.", at_position, found_integer)
            }
            DecodeError::VarOpaqueExceedsMaxLength { at_position, max_length, actual_length } => {
                write!(f, "The 'Var Opaque' at position {} exceeds the max length of {}. Actual length: {}.", at_position, max_length, actual_length)
            }
            DecodeError::StringExceedsMaxLength { at_position, max_length, actual_length } => {
                write!(f, "The string at position {} exceeds the max length of {}. Actual length: {}.", at_position, max_length, actual_length)
            }
            DecodeError::VarArrayExceedsMaxLength { at_position, max_length, actual_length } => {
                write!(f, "The 'Var Array' at position {} exceeds the max length of {}. Actual length: {}.", at_position, max_length, actual_length)
            }
            DecodeError::InvalidOptional { at_position, has_code } => {
                write!(f, "Invalid 'Optional' at position {}. Found code: {}.", at_position, has_code)
            }
            DecodeError::InvalidEnumDiscriminator { at_position } => {
                write!(f, "Invalid enum discriminator at position {}.", at_position)
            }
            DecodeError::InvalidBase64 => {
                write!(f, "Invalid base64 encoding.")
            }
            DecodeError::InvalidXdrArchiveLength { at_position } => {
                write!(f, "Invalid length encoding in XDR stream at position {}.", at_position)
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

impl Display for W<StellarSdkError> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self.0 {
            StellarSdkError::ExceedsMaximumLength { requested_length, allowed_length } => {
                write!(f, "The requested length {} exceeds the maximum allowed length {}", requested_length, allowed_length)
            },
            _ => write!(f, "Other error")
        }
    }
}

impl Debug for W<StellarSdkError> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for W<StellarSdkError> {}

impl From<StellarSdkError> for StellarError {
    fn from(value: StellarSdkError) -> Self {
            Self::StellarSdkError(W(value))
    }
}