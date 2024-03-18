use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use identity::{PeerId, PublicKey};
use multiaddr::Multiaddr;
use multistream_select::Negotiated;
use rasi::{executor::spawn, syscall::Handle, utils::cancelable_would_block};
use rasi_ext::{
    future::event_map::EventMap,
    utils::{AsyncLockable, AsyncSpinMutex},
};

use crate::{
    errors::{P2pError, Result},
    keypair::memory::MemoryKeyProvider,
    neighbors::memory::MemoryNeighbors,
};

use super::{
    identity_response, Channel, ConnPoolOfPeers, KeypairProvider, NeighborStorage, P2pConn,
    P2pStream, ProtocolId, SwitchStream,
};

/// The immutable_switch statement of one [`Switch`]
pub(super) struct ImmutableSwitch {
    agent_version: String,
    laddrs: Vec<Multiaddr>,
    public_key: PublicKey,
    pub(super) max_identity_packet_len: usize,
    protos: Vec<ProtocolId>,
    channels: Vec<Channel>,
    neighbors: Box<dyn NeighborStorage>,
    keypair: Arc<Box<dyn KeypairProvider>>,
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
    pub(super) immutable_switch: Arc<ImmutableSwitch>,
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

    /// Get this `Siwtch`'s  [`PeerId`]
    pub fn peer_id(&self) -> PeerId {
        self.immutable_switch.public_key.to_peer_id()
    }

    /// Get the public key of this switch.
    pub fn public_key(&self) -> &PublicKey {
        &self.immutable_switch.public_key
    }

    /// Get the bound addresses of this switch.
    pub fn local_addrs(&self) -> &[Multiaddr] {
        &self.immutable_switch.laddrs
    }

    /// Get the [`agentVersion`](https://github.com/libp2p/specs/blob/master/identify/README.md) string.
    pub fn agent_version(&self) -> &str {
        &self.immutable_switch.agent_version.as_str()
    }

    /// Create new connection to `raddrs`.
    pub async fn connect(&self, raddrs: &[Multiaddr]) -> Result<P2pConn> {
        let p2p_conn = self.connect_inner(raddrs).await?;

        let p2p_conn = p2p_conn.negotiate_peer_id(self.clone()).await?;

        self.conn_pool_of_peers.put(p2p_conn.clone()).await;

        let this = self.clone();

        let acceptor = p2p_conn.clone();

        spawn(async move {
            let raddr = acceptor.peer_addr().clone();

            match this.conn_accept_loop(acceptor).await {
                Ok(_) => {
                    log::trace!("stop accept loop, raddr={:?}", raddr);
                }
                Err(err) => {
                    log::trace!("stop accept loop, raddr={:?}, err={}", raddr, err);
                }
            }
        });

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
    async fn start_listener(&self) -> Result<()> {
        for laddr in &self.immutable_switch.laddrs {
            let channel = self
                .immutable_switch
                .channel_of_multiaddr(laddr)
                .ok_or_else(|| P2pError::BindMultiAddr(laddr.clone()))?;

            let handle = cancelable_would_block(|cx| {
                channel
                    .transport
                    .bind(cx, self.immutable_switch.keypair.clone(), &laddr)
            })
            .await?;

            let this = self.clone();

            let laddr = laddr.clone();

            spawn(async move {
                match this.run_listener_loop(channel, handle, laddr.clone()).await {
                    Ok(_) => log::info!("listener {:?}, stopped", laddr),
                    Err(err) => log::error!("listener {:?}, stopped with error: {}", laddr, err),
                }
            });
        }

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

                            match this.handle_incoming_conn(newly_conn).await {
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

    async fn handle_incoming_conn(&self, p2p_conn: P2pConn) -> Result<()> {
        // fetch peer's id.
        let p2p_conn = p2p_conn.negotiate_peer_id(self.clone()).await?;

        // put the newly connection into peer pool.
        self.conn_pool_of_peers.put(p2p_conn.clone()).await;

        self.conn_accept_loop(p2p_conn).await?;

        Ok(())
    }

    async fn conn_accept_loop(&self, p2p_conn: P2pConn) -> Result<()> {
        while let Some(stream) = p2p_conn.accept().await {
            let immutable_switch = self.immutable_switch.clone();
            let mutable_switch = self.mutable_switch.clone();

            // Safety: p2p_conn is identity negotiated.
            let peer_id = p2p_conn.peer_id().map(Clone::clone).unwrap();

            let this = self.clone();

            let raddr = p2p_conn.peer_addr().clone();

            spawn(async move {
                match stream
                    .server_select_protocol(&immutable_switch.protos)
                    .await
                {
                    Ok((mut stream, protocol_id)) => {
                        match this
                            .handle_core_protocols(&mut stream, &protocol_id, raddr)
                            .await
                        {
                            Ok(true) => {
                                return;
                            }
                            Err(err) => {
                                log::error!(
                                    "handle core protocol {}, returns error: {}",
                                    protocol_id,
                                    err
                                );
                                return;
                            }
                            Ok(false) => {}
                        }

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

    async fn handle_core_protocols(
        &self,
        stream: &mut Negotiated<SwitchStream>,
        protocol_id: &ProtocolId,
        raddr: Multiaddr,
    ) -> Result<bool> {
        if protocol_id.to_string() == "/ipfs/id/push/1.0.0" {
            identity_response(self, stream, raddr).await?;

            return Ok(true);
        }

        Ok(false)
    }
}

/// A builder pattern implementation for [`Switch`] type.
#[derive(Default)]
pub struct SwitchBuilder {
    agent_version: String,
    max_identity_packet_len: usize,
    keypair: Option<Box<dyn KeypairProvider>>,
    channels: Vec<Channel>,
    neighbors: Option<Box<dyn NeighborStorage>>,
    laddrs: Vec<Multiaddr>,
    protos: Vec<Result<ProtocolId>>,
}

impl SwitchBuilder {
    /// Create a [`Switch`] builder with default configuration
    pub fn new() -> Self {
        Self {
            agent_version: "/rasi/libp2p/0.0.1".to_string(),
            max_identity_packet_len: 4096,
            ..Default::default()
        }
    }

    /// Set the agent_version value, the default is `/rasi/libp2p/x.x.x`.
    ///
    /// This configuration will be used in `Identify` protocol to identify the implementation of the peer.
    pub fn set_agent_version(mut self, value: &str) -> Self {
        self.agent_version = value.to_owned();
        self
    }

    /// Set the max_identity_packet_len value, the default is `4096`
    pub fn set_max_identity_packet_len(mut self, value: usize) -> Self {
        self.max_identity_packet_len = value;
        self
    }

    /// Register a new protocol, that the switch can accept.
    ///
    /// ## Note
    ///
    /// "/ipfs/id/1.0.0" is the core protocol and will be automatically registered.
    pub fn application_protos<P, E>(mut self, protos: P) -> Self
    where
        P: IntoIterator,
        P::Item: TryInto<ProtocolId, Error = E>,
        P2pError: From<E>,
    {
        let protos = protos
            .into_iter()
            .map(|item| item.try_into().map_err(Into::into))
            .collect::<Vec<_>>();

        self.protos = protos;
        self
    }

    /// Add a new `KeyPiar` provider for the switch.
    pub fn register_keypair<K: KeypairProvider + 'static>(mut self, keypair: K) -> Self {
        self.keypair = Some(Box::new(keypair));
        self
    }

    /// Add a new `Neighbors` provider for the switch.
    pub fn register_neighbors<N: NeighborStorage + 'static>(mut self, neighbors: N) -> Self {
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
            .collect::<Result<HashSet<_>>>()?;

        let keypair = Arc::new(
            self.keypair
                .unwrap_or_else(|| Box::new(MemoryKeyProvider::default())),
        );

        let public_key = cancelable_would_block(|cx| keypair.public_key(cx)).await?;

        if self.laddrs.is_empty() {
            log::warn!("Switch created without bind any listener.");
        }

        let switch = Switch {
            immutable_switch: Arc::new(ImmutableSwitch {
                agent_version: self.agent_version,
                laddrs: self.laddrs,
                max_identity_packet_len: self.max_identity_packet_len,
                public_key,
                keypair,
                channels: self.channels,
                protos: protos.into_iter().collect::<Vec<_>>(),
                neighbors: self
                    .neighbors
                    .unwrap_or_else(|| Box::new(MemoryNeighbors::default())),
            }),

            event_map: Default::default(),
            mutable_switch: Default::default(),
            conn_pool_of_peers: Default::default(),
        };

        switch.start_listener().await?;

        Ok(switch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[futures_test::test]
    async fn test_protos_de_duplicate() {
        let switch = SwitchBuilder::new()
            .application_protos(["/echo/0.0.1", "/ipfs/id/1.0.0"])
            .create()
            .await
            .unwrap();

        assert_eq!(switch.immutable_switch.protos.len(), 2);
    }
}
