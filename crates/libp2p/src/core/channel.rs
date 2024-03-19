use std::{
    fmt::Debug,
    io,
    net::Shutdown,
    ops::Deref,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite, Future};
use identity::PublicKey;
use multiaddr::Multiaddr;
use rasi::{
    executor::spawn,
    syscall::{CancelablePoll, Handle, PendingHandle},
    utils::cancelable_would_block,
};

use crate::{errors::Result, KeypairProvider};

use super::P2pConn;

/// A service that provide asynchronous reading/writing functions.
pub trait ChannelIo: Sync + Send + Unpin {
    /// Write data via the `connection handle` to peer.
    ///
    /// On success, returns the written data length.
    fn write(
        &self,
        cx: &mut Context<'_>,
        handle: &Handle,
        buf: &[u8],
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>>;

    /// Read data via the `connection handle` from peer.
    ///
    /// On success, returns the read data length.
    fn read(
        &self,
        cx: &mut Context<'_>,
        handle: &Handle,
        buf: &mut [u8],
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>>;

    /// Shuts down the read, write, or both halves of the connection referenced by the [`handle`](Handle).
    ///
    /// This method will cause all pending and future I/O on the specified portions to return
    /// immediately with an appropriate value (see the documentation of [`Shutdown`]).
    fn shutdown(&self, handle: &Handle, how: Shutdown) -> io::Result<()>;
}

/// A trait provide accessors to handle context informations.
pub trait HandleContext {
    /// Format handle with provided [`Formatter`](std::fmt::Formatter).
    fn fmt(&self, handle: &Handle, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;

    /// Returns the connection's peer [`Multiaddr`] referenced by this handle.
    fn peer_addr<'a>(&self, handle: &'a Handle) -> &'a Multiaddr;

    /// Get the peer [`PublicKey`] used to encrypt the connection referenced by this `handle`.
    ///
    /// If the connection lack security, returns None.
    fn public_key<'a>(&self, handle: &'a Handle) -> Option<&'a PublicKey>;

    /// Tests whether the connection referenced by the handle is a server-side connection.
    fn is_server(&self, handle: &Handle) -> bool;
}

pub trait Transport: HandleContext + ChannelIo + Sync + Send {
    /// Test if this transport exact match the `addr`.
    fn multiaddr_hint(&self, addr: &Multiaddr) -> bool;

    /// Create a server-side listener and bind it on `laddr`.
    fn bind(
        &self,
        cx: &mut Context<'_>,
        keypair: Arc<Box<dyn KeypairProvider>>,
        laddr: &Multiaddr,
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<Handle>>;

    /// Accept a newly incoming transport connection.
    fn accept(
        &self,
        cx: &mut Context<'_>,
        handle: &Handle,
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<Handle>>;

    /// Create a transport connection, and connect to `raddr`.
    fn connect(
        &self,
        cx: &mut Context<'_>,
        raddr: &Multiaddr,
        keypair: Arc<Box<dyn KeypairProvider>>,
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<Handle>>;
}

pub trait SecureUpgrade: HandleContext + ChannelIo + Sync + Send {
    /// Upgrade a client `SwitchConn` to support more features.
    fn upgrade_client(
        &self,
        handle: Handle,
        transport: Arc<Box<dyn Transport>>,
        keypair: Arc<Box<dyn KeypairProvider>>,
    ) -> io::Result<Handle>;

    /// Upgrade a server `SwitchConn` to support more features.
    fn upgrade_server(
        &self,
        handle: Handle,
        transport: Arc<Box<dyn Transport>>,
        keypair: Arc<Box<dyn KeypairProvider>>,
    ) -> io::Result<Handle>;

    fn handshake(
        &self,
        cx: &mut Context<'_>,
        upgrade_handle: &Handle,
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<PublicKey>>;
}

/// A type that upgrade the [`P2pConn`] to support creating muxing bi-directional data stream.
pub trait MuxingUpgrade: HandleContext + Sync + Send {
    /// Upgrade a client `SwitchConn` to support more features.
    fn upgrade_client(
        &self,
        handle: Handle,
        secure_upgrade: Arc<Box<dyn SecureUpgrade>>,
        keypair: Arc<Box<dyn KeypairProvider>>,
    ) -> io::Result<Handle>;

    /// Upgrade a server `SwitchConn` to support more features.
    fn upgrade_server(
        &self,
        handle: Handle,
        secure_upgrade: Arc<Box<dyn SecureUpgrade>>,
        keypair: Arc<Box<dyn KeypairProvider>>,
    ) -> io::Result<Handle>;

    fn handshake(
        &self,
        cx: &mut Context<'_>,
        upgrade_handle: &Handle,
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<PublicKey>>;

    /// Accept a newly incoming muxing stream.
    fn accept(
        &self,
        cx: &mut Context<'_>,
        handle: &Handle,
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<Handle>>;

    /// Create a newly outbound muxing stream.
    fn connect(
        &self,
        cx: &mut Context<'_>,
        handle: &Handle,
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<Handle>>;

    /// Write data via the `connection handle` to peer.
    ///
    /// On success, returns the written data length.
    fn write(
        &self,
        cx: &mut Context<'_>,
        stream_handle: &Handle,
        buf: &[u8],
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>>;

    /// Read data via the `connection handle` from peer.
    ///
    /// On success, returns the read data length.
    fn read(
        &self,
        cx: &mut Context<'_>,
        stream_handle: &Handle,
        buf: &mut [u8],
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>>;

    /// Shuts down the read, write, or both halves of the connection referenced by the [`handle`](Handle).
    ///
    /// This method will cause all pending and future I/O on the specified portions to return
    /// immediately with an appropriate value (see the documentation of [`Shutdown`]).
    fn shutdown(&self, stream_handle: &Handle, how: Shutdown) -> io::Result<()>;
}

/// Transport specified upgrade workflow
#[derive(Clone)]
pub struct Upgrader {
    secure_upgrade: Arc<Box<dyn SecureUpgrade>>,
    muxing_updrade: Arc<Box<dyn MuxingUpgrade>>,
}

impl Upgrader {
    pub fn new<S, M>(secure_upgrade: S, muxing_updrade: M) -> Self
    where
        S: SecureUpgrade + 'static,
        M: MuxingUpgrade + 'static,
    {
        Self {
            secure_upgrade: Arc::new(Box::new(secure_upgrade)),
            muxing_updrade: Arc::new(Box::new(muxing_updrade)),
        }
    }

    /// Upgrade a client-side transport connection.
    pub async fn client_conn_upgrade(
        &self,
        handle: Handle,
        transport: Arc<Box<dyn Transport>>,
        keypair: Arc<Box<dyn KeypairProvider>>,
    ) -> Result<P2pConn> {
        let upgrade_handle =
            self.secure_upgrade
                .upgrade_client(handle, transport, keypair.clone())?;

        cancelable_would_block(|cx, pending| {
            self.secure_upgrade.handshake(cx, &upgrade_handle, pending)
        })
        .await?;

        let upgrade_handle = self.muxing_updrade.upgrade_client(
            upgrade_handle,
            self.secure_upgrade.clone(),
            keypair.clone(),
        )?;

        cancelable_would_block(|cx, pending| {
            self.muxing_updrade.handshake(cx, &upgrade_handle, pending)
        })
        .await?;

        Ok((Arc::new(upgrade_handle), self.muxing_updrade.clone()).into())
    }

    /// Upgrade a server-side transport connection.
    pub async fn server_conn_upgrade(
        &self,
        handle: Handle,
        transport: Arc<Box<dyn Transport>>,
        keypair: Arc<Box<dyn KeypairProvider>>,
    ) -> Result<P2pConn> {
        let upgrade_handle =
            self.secure_upgrade
                .upgrade_server(handle, transport, keypair.clone())?;

        cancelable_would_block(|cx, pending| {
            self.secure_upgrade.handshake(cx, &upgrade_handle, pending)
        })
        .await?;

        let upgrade_handle = self.muxing_updrade.upgrade_server(
            upgrade_handle,
            self.secure_upgrade.clone(),
            keypair.clone(),
        )?;

        cancelable_would_block(|cx, pending| {
            self.muxing_updrade.handshake(cx, &upgrade_handle, pending)
        })
        .await?;

        Ok((Arc::new(upgrade_handle), self.muxing_updrade.clone()).into())
    }
}

///  A channel is a bi-directional network channel maintained by a [`Switch`](super::Switch)
#[derive(Clone)]
pub struct Channel {
    pub(super) transport: Arc<Box<dyn Transport>>,
    pub(super) upgrader: Upgrader,
}

impl<T, S, M> From<(T, S, M)> for Channel
where
    T: Transport + 'static,
    S: SecureUpgrade + 'static,
    M: MuxingUpgrade + 'static,
{
    fn from((t, s, m): (T, S, M)) -> Self {
        Self {
            transport: Arc::new(Box::new(t)),
            upgrader: Upgrader::new(s, m),
        }
    }
}

impl Channel {
    /// Accept newly incoming connection, and upgrade transport connection to [`P2pConn`].
    pub async fn accept<H, Fut>(
        &self,
        listener: &Handle,
        keypair: Arc<Box<dyn KeypairProvider>>,
        handler: H,
    ) -> Result<()>
    where
        H: FnOnce(Result<P2pConn>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send,
    {
        let conn_handle =
            cancelable_would_block(|cx, pending| self.transport.accept(cx, listener, pending))
                .await?;

        let transport = self.transport.clone();
        let upgrader = self.upgrader.clone();

        spawn(async move {
            handler(
                upgrader
                    .server_conn_upgrade(conn_handle, transport.clone(), keypair)
                    .await,
            )
            .await;
        });

        Ok(())
    }

    /// Create a transport connection that connected to `raddr`, and upgrade it to [`P2pConn`].
    pub async fn connect(
        &self,
        raddr: &Multiaddr,
        keypair: Arc<Box<dyn KeypairProvider>>,
    ) -> Result<P2pConn> {
        let conn_handle = cancelable_would_block(|cx: &mut Context<'_>, pending| {
            self.transport.connect(cx, raddr, keypair.clone(), pending)
        })
        .await?;

        self.upgrader
            .client_conn_upgrade(conn_handle, self.transport.clone(), keypair)
            .await
    }
}

/// A helper type to handle p2p connection read/write operations.
pub struct SwitchConn<C> {
    pub(super) handle: Arc<Handle>,
    pub(super) channel: Arc<C>,
    write_cancel_handle: Option<PendingHandle>,
    read_cancel_handle: Option<PendingHandle>,
}

impl<C> From<(Arc<Handle>, Arc<C>)> for SwitchConn<C> {
    fn from(value: (Arc<Handle>, Arc<C>)) -> Self {
        Self {
            handle: value.0,
            channel: value.1,
            write_cancel_handle: None,
            read_cancel_handle: None,
        }
    }
}

impl<C> Debug for SwitchConn<C>
where
    C: Deref,
    C::Target: HandleContext,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.channel.fmt(&self.handle, f)
    }
}

impl<C> Clone for SwitchConn<C> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
            channel: self.channel.clone(),
            // Safety: only meaningful in the context of a poll loop.
            write_cancel_handle: None,
            // Safety: only meaningful in the context of a poll loop.
            read_cancel_handle: None,
        }
    }
}

impl<C> AsyncWrite for SwitchConn<C>
where
    C: Deref,
    C::Target: ChannelIo,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let pending = self.write_cancel_handle.take();
        match self.channel.write(cx, &self.handle, buf, pending) {
            CancelablePoll::Ready(r) => Poll::Ready(r),
            CancelablePoll::Pending(cancel) => {
                self.write_cancel_handle = Some(cancel);
                Poll::Pending
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.channel.shutdown(&self.handle, Shutdown::Both)?;
        std::task::Poll::Ready(Ok(()))
    }
}

impl<C> AsyncRead for SwitchConn<C>
where
    C: ChannelIo,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let pending = self.read_cancel_handle.take();
        match self.channel.read(cx, &self.handle, buf, pending) {
            CancelablePoll::Ready(r) => Poll::Ready(r),
            CancelablePoll::Pending(cancel) => {
                self.read_cancel_handle = Some(cancel);
                Poll::Pending
            }
        }
    }
}

impl<C> SwitchConn<C> {
    /// Get inner handle.
    pub fn to_handle(&self) -> Arc<Handle> {
        self.handle.clone()
    }

    pub fn to_channel(&self) -> Arc<C> {
        self.channel.clone()
    }
}
