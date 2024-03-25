use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error("The protocol ID is incorrectly formatted.")]
    ParseProtocolId,

    #[error(transparent)]
    ProtobufErr(#[from] protobuf::Error),

    #[error(transparent)]
    IdentityDecodingErr(#[from] identity::DecodingError),

    #[error("The peer id fetched by the Identify protocol, is mismatched with provided one or is mismatched with channel secure public key.")]
    UnexpectPeerId,

    #[error(transparent)]
    MultiaddrErr(#[from] multiaddr::Error),

    #[error(transparent)]
    NegotiationErr(#[from] multistream_select::NegotiationError),

    #[error("Can't bind listener with multiaddr {0}")]
    Bind(multiaddr::Multiaddr),

    #[error("A valid routing path to connect to the peer could not be found.")]
    RouteError,
}

impl From<Error> for io::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::IoError(io_error) => io_error,
            _ => io::Error::new(io::ErrorKind::Other, value),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
