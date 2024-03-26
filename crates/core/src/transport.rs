use std::{io, sync::Arc};

use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use identity::PeerId;
use multiaddr::Multiaddr;

use crate::BoxHostKey;

/// A type alias of [`Box<dyn Listener>`]
pub type BoxListener = Box<dyn Listener>;

/// A type alias of [`Box<dyn Transport>`]
pub type BoxTransport = Box<dyn Transport>;

/// A type alias of [`Box<dyn Connection>`]
pub type BoxConnection = Box<dyn Connection>;

/// A type alias of [`Box<dyn Stream>`]
pub type BoxStream = Box<dyn Stream>;

/// Transport is a facade of one transport layer protocol.
///
/// It provide a entry to create a client-side connection to peer or
/// create a server-side socket to accept incoming connections.
///
/// This type is used as a transport plugin and is usually injected into the `Switch` context,
/// End-users should call ***Switch-related*** functions to create a listener or create an outbound connection.
#[async_trait]
pub trait Transport: Sync + Send {
    /// Test if this transport support the `laddr`.
    fn multiaddr_hint(&self, laddr: &Multiaddr) -> bool;
    /// Create a server side socket and bind it on `laddr`.
    async fn bind(&self, host_key: Arc<BoxHostKey>, laddr: &Multiaddr) -> io::Result<BoxListener>;

    /// Create a client socket and establish one [`Connection`](Connection) to `raddr`.
    async fn connect(
        &self,
        host_key: Arc<BoxHostKey>,
        raddr: &Multiaddr,
    ) -> io::Result<BoxConnection>;
}

#[async_trait]
pub trait Listener: Sync + Send {
    async fn accept(&self) -> io::Result<BoxConnection>;

    /// Returns local bind address.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out which port was
    /// actually bound.
    fn local_addr(&self) -> io::Result<Multiaddr>;
}

/// A type that represent a transport layer connection between local and peer.
///
/// You can create the `Connection` by call function [`connect`](Transport::connect) or [`accept`](Listener::accept).
#[async_trait]
pub trait Connection: Sync + Send {
    /// Returns local bind address.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out which port was
    /// actually bound.
    fn local_addr(&self) -> io::Result<Multiaddr>;

    /// Returns the remote address that this connection is connected to.
    fn peer_addr(&self) -> io::Result<Multiaddr>;

    /// Return peer's id obtained from secure layer peer's public key.
    fn peer_id(&self) -> io::Result<PeerId>;

    /// Return the secure layer peer's public key.
    fn public_key(&self) -> io::Result<identity::PublicKey>;

    /// Open a outbound stream for reading/writing via this connection.
    async fn open(&self) -> io::Result<BoxStream>;

    /// Accept newly incoming stream for reading/writing.
    ///
    /// If the connection is dropping or has been dropped, this function will returns `None`.
    async fn accept(&self) -> io::Result<BoxStream>;

    /// Attempt to close this connection.
    async fn close(&self) -> io::Result<()>;
}

/// A stream to read/write data between local node and peer.
pub trait Stream: AsyncWrite + AsyncRead + Sync + Send + Unpin {}

impl<T> Stream for T where T: AsyncWrite + AsyncRead + Sync + Send + Unpin {}
