use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use identity::PeerId;
use multiaddr::Multiaddr;
use multistream_select::Negotiated;
use rasi::{executor::spawn, syscall::Handle, utils::cancelable_would_block};
use rasi_ext::{
    future::event_map::EventMap,
    utils::{AsyncLockable, AsyncSpinMutex},
};

use crate::{
    core::run_identity_protocol_once,
    errors::{P2pError, Result},
};

use super::{
    Channel, ConnPoolOfPeers, DefaultKeyPair, DefaultNeighbors, KeyPair, Neighbors, ProtocolId,
    SwitchConn, SwitchStream,
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
    incoming: VecDeque<(Negotiated<SwitchStream>, ProtocolId, PeerId)>,
}

/// A switch is the entry point of the libp2p network.
#[derive(Clone)]
pub struct Switch {
    immutable_switch: Arc<ImmutableSwitch>,
    mutable: Arc<AsyncSpinMutex<MutableSwitch>>,
    event_map: Arc<EventMap<SwitchEvent>>,
    conn_pool_of_peers: Arc<ConnPoolOfPeers>,
}

impl Switch {
    /// Create new connection to `raddrs`.
    pub async fn connect(&self, raddrs: &[Multiaddr]) -> Result<SwitchConn> {
        let mut last_error = None;
        for raddr in raddrs {
            if let Some(channel) = self.immutable_switch.channel_of_multiaddr(&raddr) {
                match cancelable_would_block(|cx| {
                    channel
                        .transport
                        .connect(cx, raddr, self.immutable_switch.keypair.clone())
                })
                .await
                {
                    Ok(conn) => {
                        match channel
                            .upgrader
                            .client_conn_upgrade(
                                conn,
                                channel.transport.clone(),
                                self.immutable_switch.keypair.clone(),
                            )
                            .await
                        {
                            Ok(conn) => return Ok(conn),
                            Err(err) => last_error = Some(err),
                        }
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

    /// Select one open one new connection to open a protocol stream.
    pub async fn open_stream(
        &self,
        peer_id: &PeerId,
        protos: &[ProtocolId],
    ) -> Result<(Negotiated<SwitchStream>, ProtocolId)> {
        let switch_conn = if let Some(switch_conn) = self.conn_pool_of_peers.get(peer_id).await {
            switch_conn
        } else {
            let switch_conn = self.connect(&self.neighbors_get(peer_id).await?).await?;

            let real_peer_id =
                run_identity_protocol_once(self.clone(), switch_conn.clone()).await?;

            if real_peer_id != *peer_id {
                return Err(P2pError::UnexpectPeerId);
            }

            self.conn_pool_of_peers
                .put(peer_id, switch_conn.clone())
                .await;

            switch_conn
        };

        let stream = switch_conn.open().await?;

        Ok(stream.client_select_protocol(protos).await?)
    }

    /// Accept a newly inbound stream from `peer`.
    ///
    /// On success, returns tuple `(Stream,ProtocolId,PeerId)`
    pub async fn accept(&self) -> Option<(Negotiated<SwitchStream>, ProtocolId, PeerId)> {
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
            match this.run_listener_loop(channel, handle).await {
                Ok(_) => log::info!("listener {:?}, stopped", laddr),
                Err(err) => log::error!("listener {:?}, stopped with error: {}", laddr, err),
            }
        });

        Ok(())
    }

    async fn run_listener_loop(&self, channel: Channel, listener: Handle) -> Result<()> {
        loop {
            let newly_conn =
                cancelable_would_block(|cx| channel.transport.accept(cx, &listener)).await?;

            let this = self.clone();

            let channel = channel.clone();
            spawn(async move {
                match this.run_incoming_handshake(channel, newly_conn).await {
                    Ok(_) => log::trace!("succcesfully update incoming connection."),
                    Err(err) => log::trace!("update incoming connection with error: {}", err),
                }
            });
        }
    }

    async fn run_incoming_handshake(&self, channel: Channel, newly_conn: Handle) -> Result<()> {
        let switch_conn = channel
            .upgrader
            .server_conn_upgrade(
                newly_conn,
                channel.transport.clone(),
                self.immutable_switch.keypair.clone(),
            )
            .await?;

        let peer_id = run_identity_protocol_once(self.clone(), switch_conn.clone()).await?;

        while let Some(stream) = switch_conn.accept().await {
            match stream
                .server_select_protocol(&self.immutable_switch.protos)
                .await
            {
                Ok((stream, protocol_id)) => {
                    self.mutable
                        .lock()
                        .await
                        .incoming
                        .push_back((stream, protocol_id, peer_id));
                }
                Err(err) => {
                    log::warn!("negotiation with client cause an error: {}", err);
                }
            };
        }

        Ok(())
    }
}

/// A builder pattern implementation for [`Switch`] type.
///
/// You can create a `builder` using the [`new`](Switch::new) function.
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
        let mut protos = ["/ipfs/id/1.0.0"]
            .into_iter()
            .map(|p| p.try_into().unwrap())
            .collect::<HashSet<_>>();

        for proto in self.protos {
            protos.insert(proto?);
        }

        let switch = Switch {
            immutable_switch: Arc::new(ImmutableSwitch {
                keypair: Arc::new(
                    self.keypair
                        .unwrap_or_else(|| Box::new(DefaultKeyPair::default())),
                ),
                channels: self.channels,
                protos: protos.into_iter().collect::<Vec<_>>(),
                neighbors: self
                    .neighbors
                    .unwrap_or_else(|| Box::new(DefaultNeighbors::default())),
            }),

            event_map: Default::default(),
            mutable: Default::default(),
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
