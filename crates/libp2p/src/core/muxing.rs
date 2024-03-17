use std::{io, net::Shutdown, task::Context};

use rasi::syscall::{CancelablePoll, Handle};

use super::SwitchHandle;

/// # Overview
/// libp2p is built on top of a stream abstraction and uses a bi-directional message stream to send data between peers.
/// However, relying on a single message stream over a connection between two peers can result in scalability issues
/// and bottlenecks. Each peer on either side of the connection may run multiple applications sending and waiting for
/// data over the stream. A single stream would block applications on one another, as one application would need to
/// wait for another to finish utilizing the stream before being able to send and receive its own messages.
///
/// To overcome this issue, libp2p enables applications to employ stream multiplexing.
/// Multiplexing allows for the creation of multiple “virtual” connections within a single connection.
/// This enables nodes to send multiple streams of messages over separate virtual connections,
/// providing a scalable solution that eliminates the bottleneck created by a single stream.
/// Then different applications/processes like Kademlia or GossipSub used by an application like IPFS
/// would get their own stream of data and make transmission more efficient.
/// Stream multiplexing makes it so that applications or protocols running on top of libp2p think that they’re
/// the only ones running on that connection. Another example is when HTTP/2 introduced streams into HTTP,
/// allowing for many HTTP requests in parallel on the same connection.
pub trait Multiplexing: Send + Sync {
    fn create(&self, handle: SwitchHandle) -> io::Result<Handle>;

    fn open(&self, cx: &mut Context<'_>, mux_conn: &Handle) -> CancelablePoll<io::Result<Handle>>;
    fn accept(&self, cx: &mut Context<'_>, mux_conn: &Handle)
        -> CancelablePoll<io::Result<Handle>>;

    /// Sends data on the stream to the remote address.
    ///
    /// On success, returns the number of bytes written.
    fn write(
        &self,
        cx: &mut Context<'_>,
        stream: &Handle,
        buf: &[u8],
    ) -> CancelablePoll<io::Result<usize>>;

    /// Receives data from the socket.
    ///
    /// On success, returns the number of bytes read.
    fn read(
        &self,
        cx: &mut Context<'_>,
        stream: &Handle,
        buf: &mut [u8],
    ) -> CancelablePoll<io::Result<usize>>;

    fn shutdown(&self, connectoin_or_stream: &Handle, how: Shutdown) -> io::Result<()>;
}

#[derive(Default)]
pub struct Yamux {}

#[allow(unused)]
impl Multiplexing for Yamux {
    fn create(&self, handle: SwitchHandle) -> io::Result<Handle> {
        todo!()
    }

    fn open(&self, cx: &mut Context<'_>, mux_conn: &Handle) -> CancelablePoll<io::Result<Handle>> {
        todo!()
    }

    fn accept(
        &self,
        cx: &mut Context<'_>,
        mux_conn: &Handle,
    ) -> CancelablePoll<io::Result<Handle>> {
        todo!()
    }

    fn write(
        &self,
        cx: &mut Context<'_>,
        stream: &Handle,
        buf: &[u8],
    ) -> CancelablePoll<io::Result<usize>> {
        todo!()
    }

    fn read(
        &self,
        cx: &mut Context<'_>,
        stream: &Handle,
        buf: &mut [u8],
    ) -> CancelablePoll<io::Result<usize>> {
        todo!()
    }

    fn shutdown(&self, connectoin_or_stream: &Handle, how: Shutdown) -> io::Result<()> {
        todo!()
    }
}
