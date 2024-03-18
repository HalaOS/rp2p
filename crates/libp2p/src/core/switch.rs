use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use identity::PeerId;
use multiaddr::Multiaddr;
use rasi::{executor::spawn, syscall::Handle, utils::cancelable_would_block};
use rasi_ext::{
    future::event_map::EventMap,
    utils::{AsyncLockable, AsyncSpinMutex},
};

use crate::errors::{P2pError, Result};

use super::{
    Channel, ConnPoolOfPeers, DefaultKeyPair, DefaultNeighbors, KeyPair, Neighbors, P2pConn,
    P2pStream, ProtocolId,
};

/// The immutable_switch statement of one [`Switch`]
struct ImmutableSwitch {
    protos: Vec<ProtocolId>,
    channels: Vec<Channel>,
    neighbors: Box<dyn Neighbors>,
    keypair: Arc<Box<dyn KeyPair>>,
}

impl ImmutableSwitch {
    /// Select one channel that exact match the `addr`.
    ///
    /// On success, return the cloned `Channel`.
    fn channel_of_multiaddr(&self, addr: &Multiaddr) -> Option<Channel> {
        for channel in self.channels.iter() {
            if channel.transport.multiaddr_hint(addr) {
                return Some(channel.clone());
            }
        }

        None
    }
}

#[allow(unused)]
#[derive(Debug, Hash, PartialEq, Eq, Clone, Copy)]
enum SwitchEvent {
    /// Newly incoming stream event.
    Incoming,
}

/// The mutable statement of one [`Switch`]
#[derive(Default)]
struct MutableSwitch {
    /// incoming stream fifo queue.
    incoming: VecDeque<P2pStream>,
}

/// A switch is the entry point of the libp2p network.
#[derive(Clone)]
pub struct Switch {
    immutable_switch: Arc<ImmutableSwitch>,
    mutable_switch: Arc<AsyncSpinMutex<MutableSwitch>>,
    event_map: Arc<EventMap<SwitchEvent>>,
    conn_pool_of_peers: Arc<ConnPoolOfPeers>,
}

impl Switch {
    async fn connect_inner(&self, raddrs: &[Multiaddr]) -> Result<P2pConn> {
        let mut last_error = None;
        for raddr in raddrs {
            if let Some(channel) = self.immutable_switch.channel_of_multiaddr(&raddr) {
                match channel
                    .connect(raddr, self.immutable_switch.keypair.clone())
                    .await
                {
                    Ok(conn) => {
                        return Ok(conn);
                    }
                    Err(err) => last_error = Some(err.into()),
                }
            }
        }

        if let Some(error) = last_error {
            Err(error)
        } else {
            Err(P2pError::NeighborRoutePathNotFound)
        }
    }

    /// Create new connection to `raddrs`.
    pub async fn connect(&self, raddrs: &[Multiaddr]) -> Result<P2pConn> {
        let p2p_conn = self.connect_inner(raddrs).await?;

        let p2p_conn = p2p_conn.negotiate_peer_id(self.clone()).await?;

        self.conn_pool_of_peers.put(p2p_conn.clone()).await;

        Ok(p2p_conn)
    }

    /// Open one outbound stream to `peer_id`.
    ///
    /// This function will call [`connect`](Self::connect) to create a new connection,
    /// if needed(the peer connection pool is empty).
    ///
    /// Returns [`NeighborRoutePathNotFound`](P2pError::NeighborRoutePathNotFound), if this `peer_id` has no routing information.
    pub async fn open_stream(&self, peer_id: &PeerId, protos: &[ProtocolId]) -> Result<P2pStream> {
        let p2p_conn = if let Some(p2p_conn) = self.conn_pool_of_peers.get(peer_id).await {
            p2p_conn
        } else {
            self.connect(&self.neighbors_get(peer_id).await?).await?
        };

        let stream = p2p_conn.open().await?;

        let (negotiated_stream, protocol_id) = stream.client_select_protocol(protos).await?;

        Ok((peer_id.clone(), protocol_id, negotiated_stream).into())
    }

    /// Accept a newly inbound stream from `peer`.
    ///
    /// On success, returns tuple `(Stream,ProtocolId,PeerId)`
    pub async fn accept(&self) -> Option<P2pStream> {
        let mut mutable = self.mutable_switch.lock().await;

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
                    mutable = self.mutable_switch.lock().await;
                }
            }
        }
    }

    /// manually update a route for the neighbor peer by [`id`](PeerId).
    pub async fn neighbors_put(&self, peer_id: PeerId, raddrs: &[Multiaddr]) -> Result<()> {
        Ok(cancelable_would_block(|cx| {
            self.immutable_switch
                .neighbors
                .neighbors_put(cx, peer_id, raddrs)
        })
        .await?)
    }

    /// Returns a copy of route table of one neighbor peer by [`id`](PeerId).
    pub async fn neighbors_get(&self, peer_id: &PeerId) -> Result<Vec<Multiaddr>> {
        Ok(
            cancelable_would_block(|cx| self.immutable_switch.neighbors.neighbors_get(cx, peer_id))
                .await?,
        )
    }

    /// remove some route information from neighbor peer by [`id`](PeerId).
    pub async fn neighbors_delete(&self, peer_id: &PeerId, raddrs: &[Multiaddr]) -> Result<()> {
        Ok(cancelable_would_block(|cx| {
            self.immutable_switch
                .neighbors
                .neighbors_delete(cx, peer_id, raddrs)
        })
        .await?)
    }

    /// Completely, remove the route table of one neighbor peer by [`id`](PeerId).
    pub async fn neighbors_delete_all(&self, peer_id: &PeerId) -> Result<()> {
        Ok(cancelable_would_block(|cx| {
            self.immutable_switch
                .neighbors
                .neighbors_delete_all(cx, peer_id)
        })
        .await?)
    }
}

impl Switch {
    async fn start_listener(&self, laddr: Multiaddr) -> Result<()> {
        let channel = self
            .immutable_switch
            .channel_of_multiaddr(&laddr)
            .ok_or_else(|| P2pError::BindMultiAddr(laddr.clone()))?;

        let handle = cancelable_would_block(|cx| {
            channel
                .transport
                .bind(cx, self.immutable_switch.keypair.clone(), &laddr)
        })
        .await?;

        let this = self.clone();

        spawn(async move {
            match this.run_listener_loop(channel, handle, laddr.clone()).await {
                Ok(_) => log::info!("listener {:?}, stopped", laddr),
                Err(err) => log::error!("listener {:?}, stopped with error: {}", laddr, err),
            }
        });

        Ok(())
    }

    async fn run_listener_loop(
        &self,
        channel: Channel,
        listener: Handle,
        laddr: Multiaddr,
    ) -> Result<()> {
        loop {
            let this = self.clone();
            let laddr = laddr.clone();

            channel
                .accept(
                    &listener,
                    self.immutable_switch.keypair.clone(),
                    |newly_conn| {
                        let this = this;

                        async move {
                            if let Err(err) = newly_conn {
                                log::error!(
                                    "{}, Accept new incoming connection with error: {}",
                                    laddr,
                                    err
                                );
                                return;
                            }

                            let newly_conn = newly_conn.unwrap();

                            match this.run_incoming_handshake(newly_conn).await {
                                Ok(_) => log::trace!("succcesfully update incoming connection."),
                                Err(err) => {
                                    log::trace!("update incoming connection with error: {}", err)
                                }
                            }
                        }
                    },
                )
                .await?;
        }
    }

    async fn run_incoming_handshake(&self, p2p_conn: P2pConn) -> Result<()> {
        // fetch peer's id.
        let p2p_conn = p2p_conn.negotiate_peer_id(self.clone()).await?;

        // put the newly connection into peer pool.
        self.conn_pool_of_peers.put(p2p_conn.clone()).await;

        while let Some(stream) = p2p_conn.accept().await {
            let immutable_switch = self.immutable_switch.clone();
            let mutable_switch = self.mutable_switch.clone();

            // Safety: p2p_conn is identity negotiated.
            let peer_id = p2p_conn.peer_id().map(Clone::clone).unwrap();

            spawn(async move {
                match stream
                    .server_select_protocol(&immutable_switch.protos)
                    .await
                {
                    Ok((stream, protocol_id)) => {
                        mutable_switch
                            .lock()
                            .await
                            .incoming
                            .push_back((peer_id, protocol_id, stream).into());
                    }
                    Err(err) => {
                        log::warn!("negotiation with client cause an error: {}", err);
                    }
                };
            });
        }

        Ok(())
    }
}

/// A builder pattern implementation for [`Switch`] type.
#[derive(Default)]
pub struct SwitchBuilder {
    keypair: Option<Box<dyn KeyPair>>,
    channels: Vec<Channel>,
    neighbors: Option<Box<dyn Neighbors>>,
    laddrs: Vec<Multiaddr>,
    protos: Vec<Result<ProtocolId>>,
}

impl SwitchBuilder {
    /// Create a [`Switch`] builder with default configuration
    pub fn new() -> Self {
        Default::default()
    }

    /// Register a new protocol, that the switch can accept.
    ///
    /// ## Note
    ///
    /// "/ipfs/id/1.0.0" is the core protocol and will be automatically registered.
    pub fn accept_protocol<P>(mut self, protocol: P) -> Self
    where
        P: TryInto<ProtocolId>,
        P2pError: From<P::Error>,
    {
        self.protos.push(protocol.try_into().map_err(Into::into));
        self
    }

    /// Add a new `KeyPiar` provider for the switch.
    pub fn register_keypair<K: KeyPair + 'static>(mut self, keypair: K) -> Self {
        self.keypair = Some(Box::new(keypair));
        self
    }

    /// Add a new `Neighbors` provider for the switch.
    pub fn register_neighbors<N: Neighbors + 'static>(mut self, neighbors: N) -> Self {
        self.neighbors = Some(Box::new(neighbors));
        self
    }

    /// Add a new transport provider for the switch.
    ///
    /// Allows multiple registrations of the same transport type with different configurations.
    pub fn register_channel<C: Into<Channel>>(mut self, channel: C) -> Self {
        self.channels.push(channel.into());
        self
    }

    /// Set the switch's listener binding addresses.
    pub fn bind<A>(mut self, local_addrs: A) -> Self
    where
        A: IntoIterator<Item = Multiaddr>,
    {
        self.laddrs = local_addrs.into_iter().collect::<Vec<_>>();

        self
    }

    /// Consume the `builder` and generate a new [`Switch`] instance.
    pub async fn create(self) -> Result<Switch> {
        let protos = ["/ipfs/id/1.0.0"]
            .into_iter()
            .map(|p| p.try_into())
            .chain(self.protos.into_iter())
            .collect::<Result<HashSet<_>>>();

        let switch = Switch {
            immutable_switch: Arc::new(ImmutableSwitch {
                keypair: Arc::new(
                    self.keypair
                        .unwrap_or_else(|| Box::new(DefaultKeyPair::default())),
                ),
                channels: self.channels,
                protos: protos?.into_iter().collect::<Vec<_>>(),
                neighbors: self
                    .neighbors
                    .unwrap_or_else(|| Box::new(DefaultNeighbors::default())),
            }),

            event_map: Default::default(),
            mutable_switch: Default::default(),
            conn_pool_of_peers: Default::default(),
        };

        if self.laddrs.is_empty() {
            log::warn!("Switch created without bind any listener.");
        }

        for laddr in self.laddrs {
            switch.start_listener(laddr).await?;
        }

        Ok(switch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[futures_test::test]
    async fn test_protos_de_duplicate() {
        let switch = SwitchBuilder::new()
            .accept_protocol("/echo/0.0.1")
            .accept_protocol("/ipfs/id/1.0.0")
            .create()
            .await
            .unwrap();

        assert_eq!(switch.immutable_switch.protos.len(), 2);
    }
}
