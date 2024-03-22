use std::{
    hash::Hash,
    io,
    net::Shutdown,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::{AsyncRead, AsyncWrite};
use identity::PeerId;
use multiaddr::Multiaddr;
use multistream_select::{dialer_select_proto, listener_select_proto, Negotiated, Version};
use rasi::{
    syscall::{CancelablePoll, Handle},
    utils::cancelable_would_block,
};

use crate::errors::Result;

use super::{MuxingUpgrade, ProtocolId};

/// A variant type of switch connections, that can be created by:
///
/// - A `MuxingUpgrade` service, user may call the [`upgrade_client`](super::MuxingUpgrade::upgrade_client) function or
/// the [`upgrade_server`](super::MuxingUpgrade::upgrade_server) function to create the upgraded connection.
#[derive(Clone)]
pub struct P2pConn {
    handle: Arc<Handle>,
    muxing: Arc<Box<dyn MuxingUpgrade>>,
}

impl PartialEq for P2pConn {
    fn eq(&self, other: &Self) -> bool {
        self.handle == other.handle
    }
}

impl Eq for P2pConn {}

impl Hash for P2pConn {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.handle.hash(state)
    }
}

impl From<(Arc<Handle>, Arc<Box<dyn MuxingUpgrade>>)> for P2pConn {
    fn from(value: (Arc<Handle>, Arc<Box<dyn MuxingUpgrade>>)) -> Self {
        Self {
            handle: value.0,
            muxing: value.1,
        }
    }
}

impl P2pConn {
    /// Get `P2pConn`'s inner handle.
    pub fn to_handle(&self) -> Arc<Handle> {
        self.handle.clone()
    }

    /// Get the [`PeerId`] of this connection peer.
    pub fn peer_id(&self) -> PeerId {
        self.muxing.public_key(&self.handle).expect("").to_peer_id()
    }

    /// Returns peer observed address of this connection.
    pub fn peer_addr(&self) -> Multiaddr {
        self.muxing.peer_addr(&self.handle)
    }

    /// Tests whether the connection referenced by the handle is a server-side connection.
    pub fn is_server(&self) -> bool {
        self.muxing.is_server(&self.handle)
    }

    /// Open a outbound stream with suggestion protocols.
    pub async fn open<P>(&self, protos: P) -> Result<P2pStream>
    where
        P: IntoIterator<Item = ProtocolId>,
    {
        let stream_handle =
            cancelable_would_block(|cx| self.muxing.connect(cx, &self.handle)).await?;

        let stream = SwitchStream::new(self.clone(), stream_handle);

        let protos = protos.into_iter().collect::<Vec<_>>();

        let (stream, protocol_id) = stream.client_select_protocol(&protos).await?;

        Ok((self.clone(), protocol_id, stream).into())
    }

    /// Accept a newly incoming stream with suggestion protocols.
    pub async fn accept<P>(&self, protos: P) -> Result<P2pStream>
    where
        P: IntoIterator<Item = ProtocolId>,
    {
        let stream_handle =
            cancelable_would_block(|cx| self.muxing.accept(cx, &self.handle)).await?;

        let stream = SwitchStream::new(self.clone(), stream_handle);

        let (stream, protocol_id) = stream
            .server_select_protocol(&protos.into_iter().collect::<Vec<_>>())
            .await?;

        Ok((self.clone(), protocol_id, stream).into())
    }
}

/// A raw data stream, that the protocol is not yet negotiated.
pub(super) struct SwitchStream {
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
        let protocols = protocols
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();

        let (id, negotiated) = dialer_select_proto(self, protocols, Version::V1).await?;

        Ok((negotiated, id.try_into()?))
    }

    /// Start server-side negotiation process.
    pub async fn server_select_protocol(
        self,
        protocols: &[ProtocolId],
    ) -> Result<(Negotiated<SwitchStream>, ProtocolId)> {
        let protocols = protocols
            .iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();

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
        match self.conn.muxing.write(cx, &self.stream_handle, buf) {
            CancelablePoll::Ready(r) => Poll::Ready(r),
            CancelablePoll::Pending(handle) => {
                self.read_cancel_handle = handle;
                Poll::Pending
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
        match self.conn.muxing.write(cx, &self.stream_handle, buf) {
            CancelablePoll::Ready(r) => Poll::Ready(r),
            CancelablePoll::Pending(handle) => {
                self.write_cancel_handle = handle;
                Poll::Pending
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
        self.conn
            .muxing
            .shutdown(&self.stream_handle, Shutdown::Both)?;

        Poll::Ready(Ok(()))
    }
}

/// A p2p stream type that the protocol has been negotiated.
pub struct P2pStream {
    protocol_id: ProtocolId,
    conn: P2pConn,
    negotiated_stream: Negotiated<SwitchStream>,
}

impl From<(P2pConn, ProtocolId, Negotiated<SwitchStream>)> for P2pStream {
    fn from(value: (P2pConn, ProtocolId, Negotiated<SwitchStream>)) -> Self {
        Self {
            conn: value.0,
            protocol_id: value.1,
            negotiated_stream: value.2,
        }
    }
}

impl AsyncRead for P2pStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.negotiated_stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for P2pStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.negotiated_stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.negotiated_stream).poll_flush(cx)
    }

    fn poll_close(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.negotiated_stream).poll_close(cx)
    }
}

impl P2pStream {
    /// Returns the [`peer id`] for this stream.
    pub fn peer_id(&self) -> PeerId {
        self.conn.peer_id()
    }

    /// Returns the negotiated [`ProtocolId`] .
    pub fn protocol_id(&self) -> &ProtocolId {
        &self.protocol_id
    }

    /// Returns peer observed address of this stream.
    pub fn peer_addr(&self) -> Multiaddr {
        self.conn.peer_addr()
    }
}
