//! When you make a connection from your computer to a machine on the internet,
//! chances are pretty good you’re sending your bits and bytes using TCP/IP,
//! the wildly successful combination of the Internet Protocol,
//! which handles addressing and delivery of data packets, and the Transmission Control Protocol,
//! which ensures that the data that gets sent over the wire is received completely and in the right order.
//!
//! Because TCP/IP is so ubiquitous and well-supported, it’s often the default choice for networked applications.
//! In some cases, TCP adds too much overhead, so applications might use UDP,
//! a much simpler protocol with no guarantees about reliability or ordering.
//!
//! While TCP and UDP (together with IP) are the most common protocols in use today,
//! they are by no means the only options. Alternatives exist at lower levels
//! (e.g. sending raw ethernet packets or bluetooth frames), and higher levels
//! (e.g. QUIC, which is layered over UDP).
//!
//! The foundational protocols that move bits around are called transports,
//! and one of libp2p’s core requirements is to be transport agnostic.
//! This means that the decision of what transport protocol to use is up to the developer,
//! and an application can support many different transports at the same time.

use std::{io, net::Shutdown, task::Waker};

use multiaddr::Multiaddr;
use rasi::syscall::{CancelablePoll, Handle};

/// A trait that pepresents the characteristics of the libp2p transport concept.
///
/// Transports are defined in terms of two core operations, listening and dialing.
///
/// Listening means that you can accept incoming connections from other peers,
/// using whatever facility is provided by the transport implementation.
/// For example, a TCP transport on a unix platform could use the bind and listen
/// system calls to have the operating system route traffic on a given TCP port
/// to the application.
///
/// Dialing is the process of opening an outgoing connection to a listening peer.
/// Like listening, the specifics are determined by the implementation,
/// but every transport in a libp2p implementation will share the same programmatic interface.
///
/// In layman's terms, this type is a `builder` for the underlying protocol's client connections and server listeners.
pub trait Transport {
    /// Returns if this transport support this `multiaddr`
    fn multiaddr_hint(&self, multiaddr: &Multiaddr) -> bool;

    /// Create a new transport listener and bind it to `multiaddr`.
    ///
    /// The listener will be closed when the returns handle drops.
    fn bind(&self, waker: Waker, multiaddr: &Multiaddr) -> CancelablePoll<io::Result<Handle>>;

    /// Accept a newly incoming transport connection.
    ///
    /// On success, returns the transport's bi-directional stream handle.
    fn accept(&self, waker: Waker, listener: &Handle) -> CancelablePoll<io::Result<Handle>>;

    /// Create a new transport socket and establish a connection to `raddr`.
    fn connect(&self, waker: Waker, raddr: &Multiaddr) -> CancelablePoll<io::Result<Handle>>;

    /// Shutdown the reading and writing portions of the transport connection.
    ///
    /// # Parameters
    /// - ***stream*** The handle of transport's bi-directional stream.
    fn shutdown(&self, stream: &Handle, how: Shutdown) -> io::Result<()>;

    /// Sends data on the stream to the remote address.
    ///
    /// On success, returns the number of bytes written.
    fn write(&self, stream: &Handle, buf: &[u8]) -> CancelablePoll<io::Result<usize>>;

    /// Receives data from the socket.
    ///
    /// On success, returns the number of bytes read.
    fn read(&self, stream: &Handle, buf: &mut [u8]) -> CancelablePoll<io::Result<usize>>;
}
