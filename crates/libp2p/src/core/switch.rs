use std::{
    borrow::Borrow,
    collections::VecDeque,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use futures::{AsyncRead, AsyncWrite};
use identity::PeerId;
use multiaddr::Multiaddr;
use multistream_select::{dialer_select_proto, Negotiated, Version};
use rasi::{syscall::Handle, utils::cancelable_would_block};
use rasi_ext::{
    future::event_map::EventMap,
    utils::{AsyncLockable, AsyncSpinMutex},
};

use crate::errors::{P2pError, Result};

use super::{
    pool::MuxingPool, KeyPairManager, MemoryNeighbors, Multiplexing, Neighbors, ProtocolId,
    SecureUpgrade, TlsHandshake, Transport, TransportType, Yamux,
};

/// Switch object reference id.
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct SwitchId(usize);

impl SwitchId {
    /// Generate a new `SwitchId`
    pub fn next() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

/// A transport handle that combine the `upgrade` context information.
pub enum SwitchHandle {
    /// Native transport handle.
    Transport(SwitchId, Handle),

    /// With secure upgraded handle.
    SecureUpgrade(SwitchId, Handle),

    /// With muxing upgraded handle.
    MuxingUpgrade {
        stream_handle: Handle,
        connection_handle: Arc<Handle>,
    },
}

impl AsyncWrite for SwitchHandle {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        todo!()
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        todo!()
    }
}

impl AsyncRead for SwitchHandle {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        todo!()
    }
}

/// The bi-directional message stream to send data between peers,
/// that created by function [`Switch::connect`] or function [`Switch::accept`].
#[allow(unused)]
pub struct SwitchStream {
    peer_id: PeerId,
    protocol_id: ProtocolId,
    negotiated_handle: Negotiated<SwitchHandle>,
}

#[allow(unused)]
/// The immutable context data of switch.
struct SwitchImmutable {
    keypair: Box<dyn KeyPairManager>,
    transports: Vec<Box<dyn Transport>>,
    muxing: Box<dyn Multiplexing>,
    secure_upgrade: Box<dyn SecureUpgrade>,
    neigbhors: Box<dyn Neighbors>,
}

/// The incoming stream channel.
#[derive(Default)]
struct SwitchMutable {
    /// incoming stream fifo queue.
    incoming: VecDeque<SwitchStream>,
}

#[allow(unused)]
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
enum SwitchEvent {
    /// Newly incoming stream event.
    Incoming,
}

/// A switch is entry of the libp2p network.
///
/// This is the first thing you create when using libp2p.
/// Its primary use is to dail an outbound connection and accept newly incoming connection.
///
/// Creates a switch [`builder`](SwitchBuilder) by calling the function [`new`](Switch::new),
/// with this `builder`, the developer can control the configuration details of the `Switch`:
///
/// * configure the transport stack.
/// * configure the secure upgrader instance.
/// * configure the muxing upgrader instance.
#[allow(unused)]
pub struct Switch {
    immutable: Arc<SwitchImmutable>,
    mutable: Arc<AsyncSpinMutex<SwitchMutable>>,
    event_map: Arc<EventMap<SwitchEvent>>,
    mux_pool: Arc<MuxingPool>,
}

impl Switch {
    /// Create a new switch [`builder`](SwitchBuilder) with provided `keypair` to configure the new `Switch`.
    pub fn new<K: KeyPairManager + 'static>(keypair: K) -> SwitchBuilder {
        SwitchBuilder {
            keypair_manager: Box::new(keypair),
            transports: Default::default(),
            muxing: Default::default(),
            secure_upgrade: Default::default(),
            neigbhors: Default::default(),
        }
    }

    /// Create a newly outbound stream to `peer` with the `protocol_id` request.
    ///
    /// If this function can't find a valid route path to create a direct connection between local and peer,
    /// returns the error [`NeighborRoutePathNotFound`](crate::errors::P2pError::NeighborRoutePathNotFound).
    ///
    /// If there is no exact match `transport` to create connection between local and peer, returns the error
    /// [`TransportNotFound`](crate::errors::P2pError::TransportNotFound).
    ///
    /// This function receives a set of protocols and uses [`multistream-select`](https://github.com/multiformats/multistream-select)
    /// protocol internally to negotiate with the peer about which application layer protocol to be used with the opening stream.
    pub async fn connect(&self, peer_id: PeerId, protos: &[ProtocolId]) -> Result<SwitchStream> {
        let stream_handle = if let Some(stream_handle) = self
            .mux_pool
            .connect(&*self.immutable.muxing, &peer_id)
            .await
        {
            stream_handle
        } else {
            self.dial_by_peer_id(&peer_id).await?
        };

        let protos = protos.iter().map(|p| p.to_string());

        let (protocol, negotiated_handle) =
            dialer_select_proto(stream_handle, protos, Version::V1).await?;

        Ok(SwitchStream {
            peer_id,
            protocol_id: protocol.try_into()?,
            negotiated_handle,
        })
    }

    async fn dial_by_peer_id(&self, peer_id: &PeerId) -> Result<SwitchHandle> {
        let mut lastest_error = None;
        let mut newly_conn = None;
        // loop neighbor's public listening addresses to find a valid transport.
        'out: for raddr in self.neighbors_get(&peer_id).await? {
            for transport in &self.immutable.transports {
                if transport.transport_hint(&raddr) {
                    match cancelable_would_block(|cx| transport.connect(cx, &raddr)).await {
                        Ok(transport_conn) => {
                            newly_conn = Some((transport_conn, transport.transport_type()));
                            break 'out;
                        }
                        Err(err) => {
                            lastest_error = Some(err);
                        }
                    }
                }
            }
        }

        if newly_conn.is_none() {
            if let Some(err) = lastest_error {
                return Err(err.into());
            }

            return Err(P2pError::ConnectToPeer);
        }

        let (newly_conn, transport_type) = newly_conn.unwrap();

        self.upgrade(newly_conn, transport_type).await
    }

    async fn upgrade(
        &self,
        newly_conn: Handle,
        transport_type: TransportType,
    ) -> Result<SwitchHandle> {
        todo!()
    }

    /// Accept a newly inbound stream from `peer`.
    ///
    /// On success, returns tuple `(switch stream, peer id, peer requested protocol id)`
    pub async fn accept(&self) -> Option<SwitchStream> {
        let mut mutable = self.mutable.lock().await;

        loop {
            if let Some(incoming) = mutable.incoming.pop_front() {
                return Some(incoming);
            }

            // sleep and waiting `Incoming` event.
            match self.event_map.once(SwitchEvent::Incoming, mutable).await {
                Err(err) => {
                    // the switch is dropping or has been closed.
                    log::info!("cancel accept process, switch closed. {:?}", err);
                    return None;
                }
                _ => {
                    // relock the mutable state again.
                    mutable = self.mutable.lock().await;
                }
            }
        }
    }

    /// Create a transport listener and bind it on `local_addr`.
    ///
    /// On success, returns the [`SwitchId`] of listener.
    ///
    /// If there is no exact match `transport` to create incoming connection listener, returns the error
    /// [`TransportNotFound`](crate::errors::P2pError::TransportNotFound).
    pub async fn bind<M: Borrow<Multiaddr>>(&self, _local_addr: M) -> Result<SwitchId> {
        todo!()
    }

    /// The batch bind function to create a group of listeners.
    ///
    /// On success, returns the [`SwitchId`] of the listeners.
    pub async fn bind_all(&self, local_addrs: &[Multiaddr]) -> Result<Vec<SwitchId>> {
        let mut ids = vec![];

        for laddr in local_addrs {
            ids.push(self.bind(laddr).await?);
        }

        Ok(ids)
    }

    /// Close and remove the transport listener from this switch by `id`
    pub fn shutdown(&self, _id: SwitchId) {}

    /// manually update a route for the neighbor peer by [`id`](PeerId).
    pub async fn neighbors_put(&self, peer_id: PeerId, raddrs: &[Multiaddr]) -> Result<()> {
        Ok(
            cancelable_would_block(|cx| {
                self.immutable.neigbhors.neighbors_put(cx, peer_id, raddrs)
            })
            .await?,
        )
    }

    /// Returns a copy of route table of one neighbor peer by [`id`](PeerId).
    pub async fn neighbors_get(&self, peer_id: &PeerId) -> Result<Vec<Multiaddr>> {
        Ok(
            cancelable_would_block(|cx| self.immutable.neigbhors.neighbors_get(cx, peer_id))
                .await?,
        )
    }

    /// remove some route information from neighbor peer by [`id`](PeerId).
    pub async fn neighbors_delete(&self, peer_id: &PeerId, raddrs: &[Multiaddr]) -> Result<()> {
        Ok(cancelable_would_block(|cx| {
            self.immutable
                .neigbhors
                .neighbors_delete(cx, peer_id, raddrs)
        })
        .await?)
    }

    /// Completely, remove the route table of one neighbor peer by [`id`](PeerId).
    pub async fn neighbors_delete_all(&self, peer_id: &PeerId) -> Result<()> {
        Ok(
            cancelable_would_block(|cx| self.immutable.neigbhors.neighbors_delete_all(cx, peer_id))
                .await?,
        )
    }
}

/// A builder pattern implementation for [`Switch`] type.
///
/// You can create a `builder` using the [`new`](Switch::new) function.
#[allow(unused)]
pub struct SwitchBuilder {
    keypair_manager: Box<dyn KeyPairManager>,
    transports: Vec<Box<dyn Transport>>,
    muxing: Option<Box<dyn Multiplexing>>,
    secure_upgrade: Option<Box<dyn SecureUpgrade>>,
    neigbhors: Option<Box<dyn Neighbors>>,
}

impl SwitchBuilder {
    /// Add a new transport provider to the switch.
    ///
    /// Allows multiple registrations of the same transport type with different configurations.
    pub fn register_transport<T: Transport + 'static>(mut self, transport: T) -> Self {
        self.transports.push(Box::new(transport));
        self
    }

    /// Set the switch's muxing service,
    /// otherwise the builder will use [`Yamux`] as the default muxing service.
    pub fn muxing<M: Multiplexing + 'static>(mut self, value: M) -> Self {
        self.muxing = Some(Box::new(value));

        self
    }

    /// Set the switch's secure upgrade service,
    /// otherwise the builder will use [`TlsHandshake`] as the default upgrade service.
    pub fn secure_upgrade<S: SecureUpgrade + 'static>(mut self, value: S) -> Self {
        self.secure_upgrade = Some(Box::new(value));

        self
    }

    /// Consume the `builder` and generate a new [`Switch`] instance.
    pub fn create(self) -> Switch {
        Switch {
            immutable: Arc::new(SwitchImmutable {
                keypair: self.keypair_manager,
                transports: self.transports,
                muxing: self.muxing.unwrap_or(Box::new(Yamux::default())),
                secure_upgrade: self
                    .secure_upgrade
                    .unwrap_or(Box::new(TlsHandshake::default())),

                neigbhors: self
                    .neigbhors
                    .unwrap_or(Box::new(MemoryNeighbors::default())),
            }),

            event_map: Default::default(),
            mutable: Default::default(),
            mux_pool: Default::default(),
        }
    }
}
