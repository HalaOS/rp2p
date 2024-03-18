use std::{
    fmt::Debug,
    io,
    net::Shutdown,
    ops::{Deref, DerefMut},
    sync::Arc,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use identity::PeerId;
use multistream_select::{dialer_select_proto, listener_select_proto, Negotiated, Version};
use rasi::{
    syscall::{CancelablePoll, Handle},
    utils::cancelable_would_block,
};

use crate::errors::Result;

use super::{KeyPair, MuxingUpgrade, ProtocolId, SecureUpgrade, Transport};

/// Inner varaint type of [`SwitchConn`]
#[derive(Clone)]
enum SwitchConnType {
    /// Connection converted from a [`Transport`] connection.
    Transport(Arc<Handle>, Arc<Box<dyn Transport>>),

    /// Connection converted from a [`SecureUpgrade`] connection.
    SecureUpgrade(Arc<Handle>, Arc<Box<dyn SecureUpgrade>>),

    /// Connection converted from a [`MuxingUpgrade`] connection.
    MuxingUpgrade(Arc<Handle>, Arc<Box<dyn MuxingUpgrade>>),
}

/// A variant type of switch connections, that can be created by two way:
///
/// - A `Transport` service, user may call the [`connect`] function or the [`accept`] function to create the native transport connection.
/// - A `XxxUpgrade` service, user may call the [`upgrade_client`] function or the [`upgrade_server`] function to create the upgraded connection.
pub struct P2pConn {
    variant: SwitchConnType,
    read_cancel_handle: Option<Handle>,
    write_cancel_handle: Option<Handle>,
}

impl Clone for P2pConn {
    fn clone(&self) -> Self {
        Self {
            variant: self.variant.clone(),
            // Safety: only meaningful in the context of a poll loop.
            read_cancel_handle: None,
            // Safety: only meaningful in the context of a poll loop.
            write_cancel_handle: None,
        }
    }
}

impl From<(Handle, Arc<Box<dyn Transport>>)> for P2pConn {
    fn from((handle, service): (Handle, Arc<Box<dyn Transport>>)) -> Self {
        Self {
            variant: SwitchConnType::Transport(Arc::new(handle), service),
            read_cancel_handle: None,
            write_cancel_handle: None,
        }
    }
}

impl From<(Handle, Arc<Box<dyn SecureUpgrade>>)> for P2pConn {
    fn from((handle, service): (Handle, Arc<Box<dyn SecureUpgrade>>)) -> Self {
        Self {
            variant: SwitchConnType::SecureUpgrade(Arc::new(handle), service),
            read_cancel_handle: None,
            write_cancel_handle: None,
        }
    }
}
impl From<(Handle, Arc<Box<dyn MuxingUpgrade>>)> for P2pConn {
    fn from((handle, service): (Handle, Arc<Box<dyn MuxingUpgrade>>)) -> Self {
        Self {
            variant: SwitchConnType::MuxingUpgrade(Arc::new(handle), service),
            read_cancel_handle: None,
            write_cancel_handle: None,
        }
    }
}

impl AsyncRead for P2pConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match &self.variant {
            SwitchConnType::Transport(handle, service) => match service.write(cx, handle, buf) {
                CancelablePoll::Ready(r) => Poll::Ready(r),
                CancelablePoll::Pending(handle) => {
                    self.read_cancel_handle = Some(handle);
                    Poll::Pending
                }
            },
            SwitchConnType::SecureUpgrade(handle, service) => {
                match service.write(cx, handle, buf) {
                    CancelablePoll::Ready(r) => Poll::Ready(r),
                    CancelablePoll::Pending(handle) => {
                        self.read_cancel_handle = Some(handle);
                        Poll::Pending
                    }
                }
            }
            SwitchConnType::MuxingUpgrade(_, _) => {
                panic!("Calling poll_read on an MuxingUpgrade connection is forbidden.");
            }
        }
    }
}

impl AsyncWrite for P2pConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match &self.variant {
            SwitchConnType::Transport(handle, service) => match service.write(cx, handle, buf) {
                CancelablePoll::Ready(r) => Poll::Ready(r),
                CancelablePoll::Pending(handle) => {
                    self.write_cancel_handle = Some(handle);
                    Poll::Pending
                }
            },
            SwitchConnType::SecureUpgrade(handle, service) => {
                match service.write(cx, handle, buf) {
                    CancelablePoll::Ready(r) => Poll::Ready(r),
                    CancelablePoll::Pending(handle) => {
                        self.write_cancel_handle = Some(handle);
                        Poll::Pending
                    }
                }
            }
            SwitchConnType::MuxingUpgrade(_, _) => {
                panic!("Calling poll_write on an MuxingUpgrade connection is forbidden.");
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match &self.variant {
            SwitchConnType::Transport(handle, service) => {
                service.shutdown(handle, Shutdown::Both)?;
            }
            SwitchConnType::SecureUpgrade(handle, service) => {
                service.shutdown(handle, Shutdown::Both)?;
            }
            SwitchConnType::MuxingUpgrade(handle, service) => {
                service.shutdown(handle, Shutdown::Both)?;
            }
        }

        Poll::Ready(Ok(()))
    }
}

impl Debug for P2pConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.variant {
            SwitchConnType::Transport(handle, service) => service.fmt_handle(handle, f),
            SwitchConnType::SecureUpgrade(handle, service) => service.fmt_handle(handle, f),
            SwitchConnType::MuxingUpgrade(handle, service) => service.fmt_handle(handle, f),
        }
    }
}

impl P2pConn {
    pub fn inner_handle(&self) -> Arc<Handle> {
        match &self.variant {
            SwitchConnType::Transport(handle, _) => handle.clone(),
            SwitchConnType::SecureUpgrade(handle, _) => handle.clone(),
            SwitchConnType::MuxingUpgrade(handle, _) => handle.clone(),
        }
    }
    /// Test if this `SwitchConn` is a transport native connection.
    pub fn is_transport_conn(&self) -> bool {
        if let SwitchConnType::Transport(_, _) = self.variant {
            true
        } else {
            false
        }
    }

    /// Test if this `SwitchConn` is a secure upgraded connection.
    pub fn is_secure_upraded_conn(&self) -> bool {
        if let SwitchConnType::SecureUpgrade(_, _) = self.variant {
            true
        } else {
            false
        }
    }

    /// Test if this `SwitchConn` is a mux upgraded connection.
    pub fn is_mux_upgraded_conn(&self) -> bool {
        if let SwitchConnType::MuxingUpgrade(_, _) = self.variant {
            true
        } else {
            false
        }
    }

    /// Using provided `SecureUpgrade` service, update client connection to support secure channel.
    pub async fn client_secure_upgrade(
        self,
        upgrade: Arc<Box<dyn SecureUpgrade>>,
        keypair: Arc<Box<dyn KeyPair>>,
    ) -> io::Result<P2pConn> {
        let upgrade_handle = upgrade.upgrade_client(self, keypair)?;

        cancelable_would_block(|cx| upgrade.handshake(cx, &upgrade_handle)).await?;

        Ok((upgrade_handle, upgrade).into())
    }

    /// Using provided `SecureUpgrade` service, update server connection to support secure channel.
    pub async fn server_secure_upgrade(
        self,
        upgrade: Arc<Box<dyn SecureUpgrade>>,
        keypair: Arc<Box<dyn KeyPair>>,
    ) -> io::Result<P2pConn> {
        let upgrade_handle = upgrade.upgrade_server(self, keypair)?;

        cancelable_would_block(|cx| upgrade.handshake(cx, &upgrade_handle)).await?;

        Ok((upgrade_handle, upgrade).into())
    }

    /// Using provided `SecureUpgrade` service, update client connection to support muxing stream.
    pub async fn client_muxing_upgrade(
        self,
        upgrade: Arc<Box<dyn MuxingUpgrade>>,
        keypair: Arc<Box<dyn KeyPair>>,
    ) -> io::Result<P2pConn> {
        let upgrade_handle = upgrade.upgrade_client(self, keypair)?;

        cancelable_would_block(|cx| upgrade.handshake(cx, &upgrade_handle)).await?;

        Ok((upgrade_handle, upgrade).into())
    }

    /// Using provided `SecureUpgrade` service, update server connection to support muxing stream.
    pub async fn server_muxing_upgrade(
        self,
        upgrade: Arc<Box<dyn MuxingUpgrade>>,
        keypair: Arc<Box<dyn KeyPair>>,
    ) -> io::Result<P2pConn> {
        let upgrade_handle = upgrade.upgrade_server(self, keypair)?;

        cancelable_would_block(|cx| upgrade.handshake(cx, &upgrade_handle)).await?;

        Ok((upgrade_handle, upgrade).into())
    }

    /// Accept new incoming muxing stream via the `MuxingUpgrade` connection.
    pub async fn accept(&self) -> Option<SwitchStream> {
        match &self.variant {
            SwitchConnType::MuxingUpgrade(handle, service) => {
                match cancelable_would_block(|cx| service.accept(cx, handle)).await {
                    Ok(stream_handle) => {
                        return Some(SwitchStream::new(self.clone(), stream_handle));
                    }
                    Err(err) => {
                        log::error!("{:?} accept muxing stream error: {}", self, err);
                        return None;
                    }
                }
            }
            _ => {
                panic!("Call accept on non MuxingUpgrade connection.")
            }
        }
    }

    /// Open a outgoing muxing stream via the `MuxingUpgrade` connection.
    pub async fn open(&self) -> Result<SwitchStream> {
        match &self.variant {
            SwitchConnType::MuxingUpgrade(handle, service) => {
                match cancelable_would_block(|cx| service.connect(cx, handle)).await {
                    Ok(stream_handle) => {
                        return Ok(SwitchStream::new(self.clone(), stream_handle));
                    }
                    Err(err) => {
                        return Err(err.into());
                    }
                }
            }
            _ => {
                panic!("Call connect on non MuxingUpgrade connection.")
            }
        }
    }
}

/// A raw data stream, that the protocol is not yet negotiated.
pub struct SwitchStream {
    /// The connection to which this stream belongs
    conn: P2pConn,

    /// muxing stream handle.5
    stream_handle: Handle,

    /// The handle to cancel write ops.
    write_cancel_handle: Option<Handle>,

    /// The handle to cancel read ops.
    read_cancel_handle: Option<Handle>,
}

impl SwitchStream {
    fn new(conn: P2pConn, stream_handle: Handle) -> Self {
        Self {
            conn,
            stream_handle,
            write_cancel_handle: None,
            read_cancel_handle: None,
        }
    }

    /// Start client-side negotiation process.
    pub async fn client_select_protocol(
        self,
        protocols: &[ProtocolId],
    ) -> Result<(Negotiated<SwitchStream>, ProtocolId)> {
        let protocols = protocols.iter().map(|id| id.to_string());

        let (id, negotiated) = dialer_select_proto(self, protocols, Version::V1).await?;

        Ok((negotiated, id.try_into()?))
    }

    /// Start server-side negotiation process.
    pub async fn server_select_protocol(
        self,
        protocols: &[ProtocolId],
    ) -> Result<(Negotiated<SwitchStream>, ProtocolId)> {
        let protocols = protocols.iter().map(|id| id.to_string());

        let (id, negotiated) = listener_select_proto(self, protocols).await?;

        Ok((negotiated, id.try_into()?))
    }
}

impl AsyncRead for SwitchStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match &self.conn.variant {
            SwitchConnType::MuxingUpgrade(_, service) => {
                match service.write(cx, &self.stream_handle, buf) {
                    CancelablePoll::Ready(r) => Poll::Ready(r),
                    CancelablePoll::Pending(handle) => {
                        self.read_cancel_handle = Some(handle);
                        Poll::Pending
                    }
                }
            }
            _ => {
                panic!(
                    "SwitchStream: Calling poll_read on non MuxingUpgrade connection is forbidden."
                );
            }
        }
    }
}

impl AsyncWrite for SwitchStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        match &self.conn.variant {
            SwitchConnType::MuxingUpgrade(_, service) => {
                match service.write(cx, &self.stream_handle, buf) {
                    CancelablePoll::Ready(r) => Poll::Ready(r),
                    CancelablePoll::Pending(handle) => {
                        self.write_cancel_handle = Some(handle);
                        Poll::Pending
                    }
                }
            }
            _ => {
                panic!(
                    "SwitchStream: Calling poll_write on non MuxingUpgrade connection is forbidden."
                );
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match &self.conn.variant {
            SwitchConnType::MuxingUpgrade(_, service) => {
                service.shutdown(&self.stream_handle, Shutdown::Both)?;
            }

            _ => {
                panic!(
                    "SwitchStream: Calling poll_write on non MuxingUpgrade connection is forbidden."
                );
            }
        }

        Poll::Ready(Ok(()))
    }
}

/// A wrapper for negotiated [`SwitchStream`].
pub struct P2pStream {
    peer_id: PeerId,
    protocol_id: ProtocolId,
    negotiated_stream: Negotiated<SwitchStream>,
}

impl From<(PeerId, ProtocolId, Negotiated<SwitchStream>)> for P2pStream {
    fn from(value: (PeerId, ProtocolId, Negotiated<SwitchStream>)) -> Self {
        Self {
            peer_id: value.0,
            protocol_id: value.1,
            negotiated_stream: value.2,
        }
    }
}

impl Deref for P2pStream {
    type Target = Negotiated<SwitchStream>;
    fn deref(&self) -> &Self::Target {
        &self.negotiated_stream
    }
}

impl DerefMut for P2pStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.negotiated_stream
    }
}

impl P2pStream {
    /// Returns the [`peer id`] for this stream.
    pub fn peer_id(&self) -> &PeerId {
        &self.peer_id
    }

    /// Returns the negotiated [`ProtocolId`] .
    pub fn protocol_id(&self) -> &ProtocolId {
        &self.protocol_id
    }
}
