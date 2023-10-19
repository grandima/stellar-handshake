use thiserror::Error;
use std::io;
use data_encoding::DecodeError;
use crate::connection_authentication::AuthenticationError;

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
    DecodeError(#[from] DecodeError),
    #[error("IO error: {0}")]
    IOError(#[from] io::Error),
    ConnectionResetByPeer,
    ExpectedMoreMessages,
    Verification(#[from] VerificationError),
}
