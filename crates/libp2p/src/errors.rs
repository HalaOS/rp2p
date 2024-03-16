use std::io;

#[derive(thiserror::Error, Debug)]
pub enum P2pError {
    #[error("libp2p protocol id should start with '/'")]
    ProtocolIdFormat,

    #[error("Register same protocol id to switch twice.")]
    RegisterProtocolId,

    #[error(transparent)]
    SemVerError(#[from] semver::Error),
}

impl From<P2pError> for io::Error {
    fn from(value: P2pError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, value)
    }
}

/// A type alias of [`Result<T, P2pError>`]
pub type P2pResult<T> = Result<T, P2pError>;
