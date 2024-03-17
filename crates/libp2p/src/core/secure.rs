use std::{io, net::Shutdown, sync::Arc, task::Context};

use rasi::syscall::{CancelablePoll, Handle};

use super::Transport;

/// # Overview
///
/// Before two peers can transmit data, the communication channel they establish needs to be secured.
/// By design, libp2p supports many different transports (TCP, QUIC, WebSocket, WebTransport, etc.).
/// Some transports have built-in encryption at the transport layer like QUIC,
/// while other transports (e.g. TCP, WebSocket) lack native security and require a security handshake
/// after the transport connection has been established.
pub trait SecureUpgrade: Sync + Send {
    /// Create client secure upgrade wrapper.
    fn client(
        &self,
        transport_handle: Handle,
        transport: Arc<Box<dyn Transport>>,
    ) -> io::Result<Handle>;

    /// Create server secure upgrade wrapper.
    fn server(
        &self,
        transport_handle: Handle,
        transport: Arc<Box<dyn Transport>>,
    ) -> io::Result<Handle>;

    fn handshake(
        &self,
        cx: &mut Context<'_>,
        secure_upgrade_handle: &Handle,
    ) -> CancelablePoll<io::Result<()>>;

    /// Sends data on the stream to the remote address.
    ///
    /// On success, returns the number of bytes written.
    fn write(
        &self,
        cx: &mut Context<'_>,
        connectoin_or_stream: &Handle,
        buf: &[u8],
    ) -> CancelablePoll<io::Result<usize>>;

    /// Receives data from the socket.
    ///
    /// On success, returns the number of bytes read.
    fn read(
        &self,
        cx: &mut Context<'_>,
        connectoin_or_stream: &Handle,
        buf: &mut [u8],
    ) -> CancelablePoll<io::Result<usize>>;

    fn shutdown(&self, connectoin_or_stream: &Handle, how: Shutdown) -> io::Result<()>;
}

#[derive(Default)]
pub struct TlsHandshake {}

#[allow(unused)]
impl SecureUpgrade for TlsHandshake {
    fn client(
        &self,
        transport_handle: Handle,
        transport: Arc<Box<dyn Transport>>,
    ) -> io::Result<Handle> {
        todo!()
    }

    fn server(
        &self,
        transport_handle: Handle,
        transport: Arc<Box<dyn Transport>>,
    ) -> io::Result<Handle> {
        todo!()
    }

    fn handshake(
        &self,
        cx: &mut Context<'_>,
        secure_upgrade_handle: &Handle,
    ) -> CancelablePoll<io::Result<()>> {
        todo!()
    }

    fn write(
        &self,
        cx: &mut Context<'_>,
        connectoin_or_stream: &Handle,
        buf: &[u8],
    ) -> CancelablePoll<io::Result<usize>> {
        todo!()
    }

    fn read(
        &self,
        cx: &mut Context<'_>,
        connectoin_or_stream: &Handle,
        buf: &mut [u8],
    ) -> CancelablePoll<io::Result<usize>> {
        todo!()
    }

    fn shutdown(&self, connectoin_or_stream: &Handle, how: Shutdown) -> io::Result<()> {
        todo!()
    }
}
