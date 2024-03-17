use std::io;

use multiaddr::Multiaddr;
use multistream_select::NegotiationError;

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

    #[error(transparent)]
    NegotiationErr(#[from] NegotiationError),
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
