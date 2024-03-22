use std::io;

use boring::error::ErrorStack;
use multiaddr::Multiaddr;
use multistream_select::NegotiationError;
use yasna::ASN1Error;

#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error("Can't find a valid route path, to create a trasnport connection.")]
    NeighborRoutePathNotFound,

    #[error("Can't find a valid transport to create a connection between local and {0}.")]
    TransportNotFound(Multiaddr),

    #[error("The protocol ID is incorrectly formatted.")]
    ParseProtocolId,

    #[error("Can't directly connect to peer for peer is not the neighbor or the no transport support peer's public listening addrs.")]
    ConnectToPeer,

    #[error("The peer id fetched by the Identify protocol, is mismatched with provided one or is mismatched with channel secure public key.")]
    UnexpectPeerId,

    #[error("Can't find property transport to start the listener with addr: {0}")]
    BindMultiAddr(Multiaddr),

    #[error(transparent)]
    NegotiationErr(#[from] NegotiationError),

    #[error(transparent)]
    ProtobufErr(#[from] protobuf::Error),

    #[error(transparent)]
    DecodingErr(#[from] identity::DecodingError),

    #[error(transparent)]
    MultiaddrErr(#[from] multiaddr::Error),

    #[error("Ping timeout or mismatched")]
    Ping,

    #[error(transparent)]
    BoringErrStack(#[from] ErrorStack),
}

impl From<P2pError> for io::Error {
    fn from(value: P2pError) -> Self {
        match value {
            P2pError::IoError(io_error) => io_error,
            _ => io::Error::new(io::ErrorKind::Other, value),
        }
    }
}

pub type Result<T> = std::result::Result<T, P2pError>;
