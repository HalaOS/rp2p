use std::{
    collections::{HashSet, VecDeque},
    fmt::Debug,
    hash::Hash,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use futures::{AsyncReadExt, AsyncWriteExt, Stream, StreamExt};
use identity::{PeerId, PublicKey};
use multiaddr::Multiaddr;
use multistream_select::{dialer_select_proto, listener_select_proto, Version};
use protobuf::Message;
use rasi::executor::spawn;
use rasi_ext::{
    future::event_map::{EventMap, EventStatus},
    utils::{AsyncLockable, AsyncSpinMutex, ReadBuf},
};

use crate::{
    proto::identify::Identify, BoxConnPool, BoxConnection, BoxHostKey, BoxListener, BoxRouteTable,
    BoxStream, BoxTransport, ConnPool, Connection, Error, HostKey, ProtocolId, Result, RouteTable,
    Transport,
};

/// stream type that the libp2p protocol has been negotiated.
pub struct P2pStream {
    protocol_id: ProtocolId,
    conn: P2pConn,
    stream: BoxStream,
}

impl P2pStream {
    /// returns underly connection's peer address.
    pub fn peer_addr(&self) -> Result<Multiaddr> {
        Ok(self.conn.peer_addr()?)
    }

    pub fn peer_id(&self) -> Result<PeerId> {
        Ok(self.conn.peer_id()?)
    }

    /// Negotiated protocol id.
    pub fn protocol_id(&self) -> &ProtocolId {
        &self.protocol_id
    }
}

impl Deref for P2pStream {
    type Target = BoxStream;
    fn deref(&self) -> &Self::Target {
        &self.stream
    }
}

impl DerefMut for P2pStream {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.stream
    }
}

/// P2p connection instance is a wraper of underly transport connection.
#[derive(Clone)]
pub struct P2pConn {
    conn: Arc<BoxConnection>,
}

impl Debug for P2pConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "p2p connection, {:?} => {:?}",
            self.conn.local_addr().unwrap_or(Multiaddr::empty()),
            self.conn.peer_addr().unwrap_or(Multiaddr::empty())
        )
    }
}

impl PartialEq for P2pConn {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::addr_eq(self.ptr(), other.ptr())
    }
}

impl Eq for P2pConn {}

impl Hash for P2pConn {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.ptr().hash(state)
    }
}

impl P2pConn {
    fn ptr(&self) -> *const dyn Connection {
        &**self.conn
    }

    fn new(conn: BoxConnection) -> Self {
        Self {
            conn: Arc::new(conn),
        }
    }
    /// Open a outbound stream with suggestion protocols.
    pub async fn open<P, I>(&self, protocols: P) -> Result<P2pStream>
    where
        P: IntoIterator<Item = I>,
        I: AsRef<str>,
    {
        let mut stream = self.conn.open().await?;

        let (protocol_id, _) = dialer_select_proto(&mut stream, protocols, Version::V1).await?;

        let protocol_id = protocol_id.as_ref().to_owned().try_into()?;

        Ok(P2pStream {
            protocol_id,
            conn: self.clone(),
            stream,
        })
    }

    /// Accept a newly incoming stream with suggestion protocols.
    async fn accept<P, I>(&self, protos: P) -> Result<P2pStream>
    where
        P: IntoIterator<Item = I>,
        I: AsRef<str> + Clone,
    {
        let mut stream = self.conn.accept().await?;

        let (protocol_id, _) = listener_select_proto(&mut stream, protos).await?;

        let protocol_id = protocol_id.as_ref().to_owned().try_into()?;

        Ok(P2pStream {
            protocol_id,
            conn: self.clone(),
            stream,
        })
    }

    /// returns underly connection's peer address.
    pub fn peer_addr(&self) -> Result<Multiaddr> {
        Ok(self.conn.peer_addr()?)
    }

    pub fn peer_id(&self) -> Result<PeerId> {
        Ok(self.conn.peer_id()?)
    }

    pub async fn close(&self) -> Result<()> {
        Ok(self.conn.close().await?)
    }
}

/// `Switch` is the network context of one libp2p application,
/// that provides an facade that allows applications to access the libp2p networks.
///
/// You should use [`SwitchBuilder`] to configure and build the `Switch` instance.
///
/// # Examples
///
/// ```no_run
/// ```
#[derive(Clone)]
pub struct Switch {
    immutable_switch: Arc<ImmutableSwitch>,
    mutable_switch: Arc<AsyncSpinMutex<MutableSwitch>>,
    event_map: Arc<EventMap<SwitchEvent>>,
}

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

struct ImmutableSwitch {
    /// switch accepted
    protos: Vec<String>,
    /// This is a free-form string, identifying the implementation of the peer. The usual format is agent-name/version,
    /// where agent-name is the name of the program or library and version is its semantic version.
    agent_version: String,
    /// The max length of identify packet.
    max_identity_packet_len: usize,
    /// Switch bound addresses.
    local_addrs: Vec<Multiaddr>,
    /// the plugin provide the ability that switch can access the host keypair functions.
    host_key: Arc<BoxHostKey>,
    /// The plugin provide the ability that the switch can access the route table functions.
    route_table: BoxRouteTable,
    /// The `ConnPool` plugin provides the ability for switch to cache transport layer connections.
    conn_pool: BoxConnPool,
    /// Registered transports.
    transports: Vec<BoxTransport>,
}

impl ImmutableSwitch {
    /// Select one channel that exact match the `addr`.
    ///
    /// On success, return the cloned `Channel`.
    fn transport_of_multiaddr(&self, addr: &Multiaddr) -> Option<&BoxTransport> {
        for transport in self.transports.iter() {
            if transport.multiaddr_hint(addr) {
                return Some(transport);
            }
        }

        None
    }
}

impl Switch {
    /// Add addresses to route table by `peer_id`.
    pub async fn route_table_put(&self, peer_id: PeerId, raddrs: &[Multiaddr]) -> Result<()> {
        Ok(self
            .immutable_switch
            .route_table
            .put(peer_id, raddrs)
            .await?)
    }

    /// Delete `addrs` from route table by `peer_id`.
    pub async fn route_table_delete(&self, peer_id: &PeerId, raddrs: &[Multiaddr]) -> Result<()> {
        Ok(self
            .immutable_switch
            .route_table
            .delete(peer_id, raddrs)
            .await?)
    }

    /// Delete all route information from route table by `peer_id`.
    pub async fn route_table_delete_all(&self, peer_id: &PeerId) -> Result<()> {
        Ok(self
            .immutable_switch
            .route_table
            .delete_all(peer_id)
            .await?)
    }

    /// Get peer's listener address.
    ///
    /// On success, returns a asynchronous [`Stream`] of listener's addresses.
    pub async fn route_table_get(
        &self,
        peer_id: &PeerId,
    ) -> Result<Option<impl Stream<Item = Multiaddr>>> {
        Ok(self.immutable_switch.route_table.get(peer_id).await?)
    }

    /// Returns host public key.
    pub async fn public_key(&self) -> Result<PublicKey> {
        Ok(self.immutable_switch.host_key.public_key().await?)
    }

    /// Get swith's `agentVersion` value.
    pub fn agent_version(&self) -> &str {
        &self.immutable_switch.agent_version
    }

    /// Get swith's local bound addresses.
    pub fn local_addrs(&self) -> impl Iterator<Item = &Multiaddr> {
        self.immutable_switch.local_addrs.iter()
    }

    /// Get the `max_identity_packet_len` configuration value.
    pub(crate) fn max_identity_packet_len(&self) -> usize {
        self.immutable_switch.max_identity_packet_len
    }

    /// Open one outbound stream to `peer_id`.
    ///
    /// This function will call [`connect`](Self::connect) to create a new connection,
    /// if needed(the peer connection pool is empty).
    ///
    /// Returns [`NeighborRoutePathNotFound`](P2pError::NeighborRoutePathNotFound), if this `peer_id` has no routing information.
    pub async fn open_stream<P, I>(&self, peer_id: &PeerId, protos: P) -> Result<P2pStream>
    where
        P: IntoIterator<Item = I>,
        I: AsRef<str>,
    {
        let conn = self.immutable_switch.conn_pool.get(peer_id).await?;

        let p2p_conn = if let Some(conn) = conn {
            conn
        } else {
            if let Some(raddrs) = self.route_table_get(peer_id).await? {
                let raddrs = raddrs.collect::<Vec<_>>().await;
                self.connect(&raddrs).await?
            } else {
                return Err(Error::RouteError);
            }
        };

        p2p_conn.open(protos).await
    }

    /// Create new connection to `raddrs`.
    pub async fn connect(&self, raddrs: &[Multiaddr]) -> Result<P2pConn> {
        let p2p_conn = self.do_connect(raddrs).await?;

        core_protocols::identity_request(self.clone(), p2p_conn.clone()).await?;

        self.immutable_switch
            .conn_pool
            .cache(p2p_conn.clone())
            .await?;

        let this = self.clone();
        let conn = p2p_conn.clone();

        spawn(async move {
            match this.hanle_connection(conn.clone()).await {
                Ok(_) => log::info!("{:?}, stopped", conn),
                Err(err) => log::error!("{:?}, stopped with error: {}", conn, err),
            }
        });

        Ok(p2p_conn)
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
}

impl Switch {
    async fn start_listener(&self) -> Result<()> {
        for laddr in &self.immutable_switch.local_addrs {
            let transport = self
                .immutable_switch
                .transport_of_multiaddr(laddr)
                .ok_or_else(|| Error::Bind(laddr.clone()))?;

            let listener = transport
                .bind(self.immutable_switch.host_key.clone(), &laddr)
                .await?;

            let this = self.clone();

            let laddr = laddr.clone();

            spawn(async move {
                match this.run_listener_loop(listener, laddr.clone()).await {
                    Ok(_) => log::info!("listener {:?}, stopped", laddr),
                    Err(err) => log::error!("listener {:?}, stopped with error: {}", laddr, err),
                }
            });
        }

        Ok(())
    }

    async fn run_listener_loop(&self, listener: BoxListener, laddr: Multiaddr) -> Result<()> {
        loop {
            let this = self.clone();
            let laddr = laddr.clone();

            let conn = listener.accept().await?;

            let conn = P2pConn::new(conn);

            spawn(async move {
                match this.hanle_connection(conn).await {
                    Ok(_) => log::info!("listener {:?}, stopped", laddr),
                    Err(err) => log::error!("listener {:?}, stopped with error: {}", laddr, err),
                }
            });
        }
    }

    async fn do_connect(&self, raddrs: &[Multiaddr]) -> Result<P2pConn> {
        let mut last_error = None;
        for raddr in raddrs {
            if let Some(transport) = self.immutable_switch.transport_of_multiaddr(&raddr) {
                match transport
                    .connect(self.immutable_switch.host_key.clone(), raddr)
                    .await
                {
                    Ok(conn) => {
                        return Ok(P2pConn::new(conn));
                    }
                    Err(err) => last_error = Some(err.into()),
                }
            }
        }

        if let Some(error) = last_error {
            Err(error)
        } else {
            Err(Error::RouteError)
        }
    }

    async fn hanle_connection(&self, p2p_conn: P2pConn) -> Result<()> {
        core_protocols::identity_request(self.clone(), p2p_conn.clone()).await?;

        // put the newly connection into peer pool.
        self.immutable_switch
            .conn_pool
            .cache(p2p_conn.clone())
            .await?;

        let r = self.conn_accept_loop(p2p_conn.clone()).await;

        _ = p2p_conn.close().await;

        self.immutable_switch.conn_pool.remove(p2p_conn).await?;

        r?;

        Ok(())
    }

    async fn conn_accept_loop(&self, p2p_conn: P2pConn) -> Result<()> {
        loop {
            let mut stream = p2p_conn
                .accept(self.immutable_switch.protos.clone())
                .await?;

            let mutable_switch = self.mutable_switch.clone();

            let mut this = self.clone();

            let event_map = self.event_map.clone();

            spawn(async move {
                match this.handle_core_protocols(&mut stream).await {
                    Ok(true) => {
                        return;
                    }
                    Ok(false) => {}
                    Err(err) => {
                        log::error!(
                            "handle core protocol {}, returns error: {}",
                            stream.protocol_id(),
                            err
                        );

                        return;
                    }
                }

                mutable_switch.lock().await.incoming.push_back(stream);

                event_map.notify(SwitchEvent::Incoming, EventStatus::Ready);
            });
        }
    }

    async fn handle_core_protocols(&mut self, stream: &mut P2pStream) -> Result<bool> {
        let protocol_id = stream.protocol_id();

        if protocol_id.to_string() == "/ipfs/id/1.0.0" {
            core_protocols::identity_response(self, stream).await?;

            return Ok(true);
        }

        if protocol_id.to_string() == "/ipfs/id/push/1.0.0" {
            core_protocols::identity_push(self, stream).await?;

            return Ok(true);
        }

        if protocol_id.to_string() == "/ipfs/ping/1.0.0" {
            core_protocols::ping_echo(stream).await?;

            return Ok(true);
        }

        return Ok(false);
    }
}

/// A builder pattern implementation for [`Switch`] type.
#[derive(Default)]
pub struct SwitchBuilder {
    agent_version: String,
    max_identity_packet_len: usize,
    laddrs: Vec<Multiaddr>,
    protos: Vec<Result<ProtocolId>>,
    transports: Vec<BoxTransport>,
    host_key: Option<BoxHostKey>,
    route_table: Option<BoxRouteTable>,
    conn_pool: Option<BoxConnPool>,
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
        Error: From<E>,
    {
        let protos = protos
            .into_iter()
            .map(|item| item.try_into().map_err(Into::into))
            .collect::<Vec<_>>();

        self.protos = protos;
        self
    }

    /// Add a new [`ConnPool`] provider for this switch.
    pub fn conn_pool<C: ConnPool + 'static>(mut self, conn_pool: C) -> Self {
        self.conn_pool = Some(Box::new(conn_pool));
        self
    }

    /// Add a new [`HostKey`] provider for this switch.
    pub fn host_key<K: HostKey + 'static>(mut self, keypair: K) -> Self {
        self.host_key = Some(Box::new(keypair));
        self
    }

    /// Add a new [`RouteTable`] provider for this switch.
    pub fn route_table<N: RouteTable + 'static>(mut self, neighbors: N) -> Self {
        self.route_table = Some(Box::new(neighbors));
        self
    }

    /// Add a new transport provider for the switch.
    ///
    /// Allows multiple registrations of the same transport type with different configurations.
    pub fn transport<T: Transport + 'static>(mut self, transport: T) -> Self {
        self.transports.push(Box::new(transport));
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
        let protos = ["/ipfs/id/1.0.0", "/ipfs/id/push/1.0.0", "/ipfs/ping/1.0.0"]
            .into_iter()
            .map(|p| p.try_into())
            .chain(self.protos.into_iter())
            .collect::<Result<HashSet<_>>>()?;

        let host_key = { Arc::new(self.host_key.expect("Must provide keypair plugin.")) };

        let route_table: Box<dyn RouteTable> =
            { self.route_table.expect("Must provide neighbors plugin.") };

        let conn_pool = { self.conn_pool.expect("Must provide conn_pool plugin.") };

        if self.laddrs.is_empty() {
            log::warn!("Switch created without bind any listener.");
        }

        let switch = Switch {
            immutable_switch: Arc::new(ImmutableSwitch {
                agent_version: self.agent_version,
                local_addrs: self.laddrs,
                max_identity_packet_len: self.max_identity_packet_len,
                host_key,
                protos: protos
                    .into_iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>(),
                transports: self.transports,
                route_table,
                conn_pool,
            }),

            event_map: Default::default(),
            mutable_switch: Default::default(),
        };

        switch.start_listener().await?;

        Ok(switch)
    }
}

mod core_protocols {
    use super::*;

    /// Handle `/ipfs/ping/1.0.0` request.
    pub(super) async fn ping_echo(stream: &mut P2pStream) -> Result<()> {
        loop {
            let mut buf = vec![0; 32];

            stream.read_exact(&mut buf).await?;

            stream.write_all(&buf).await?;
        }
    }

    /// client-side use this function to execute identify request.
    pub(super) async fn identity_request(switch: Switch, conn: P2pConn) -> Result<()> {
        let identify = {
            let mut stream = conn.open(["/ipfs/id/1.0.0"]).await?;

            let mut buf = ReadBuf::with_capacity(switch.max_identity_packet_len());

            loop {
                let read_size = stream.read(buf.chunk_mut()).await?;

                if read_size == 0 {
                    break;
                }

                buf.advance_mut(read_size);
            }

            Identify::parse_from_bytes(buf.chunk())?
        };

        let conn_peer_id = conn.peer_id()?;

        let pubkey = PublicKey::try_decode_protobuf(identify.publicKey())?;

        let peer_id = pubkey.to_peer_id();

        if conn_peer_id != peer_id {
            return Err(Error::UnexpectPeerId);
        }

        let raddrs = identify
            .listenAddrs
            .into_iter()
            .map(|buf| Multiaddr::try_from(buf).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;

        switch.route_table_put(peer_id, &raddrs).await?;

        Ok(())
    }

    /// The responsor of identify request.
    pub(super) async fn identity_response(switch: &Switch, stream: &mut P2pStream) -> Result<()> {
        let mut identity = Identify::new();

        identity.set_observedAddr(stream.peer_addr()?.to_vec());

        identity.set_publicKey(switch.public_key().await?.encode_protobuf());

        identity.set_agentVersion(switch.agent_version().to_owned());

        identity.listenAddrs = switch
            .local_addrs()
            .map(|addr| addr.to_vec())
            .collect::<Vec<_>>();

        let buf = identity.write_to_bytes()?;

        stream.write_all(&buf).await?;

        Ok(())
    }

    /// Handle `/ipfs/id/push/1.0.0` request.
    pub(super) async fn identity_push(switch: &mut Switch, stream: &mut P2pStream) -> Result<()> {
        let identify = {
            let mut buf = ReadBuf::with_capacity(switch.max_identity_packet_len());

            loop {
                let read_size = stream.read(buf.chunk_mut()).await?;

                if read_size == 0 {
                    break;
                }

                buf.advance_mut(read_size);
            }

            Identify::parse_from_bytes(buf.chunk())?
        };

        let peer_id = PublicKey::try_decode_protobuf(identify.publicKey())?.to_peer_id();

        let conn_peer_id = stream.peer_id()?;

        if conn_peer_id != peer_id {
            return Err(Error::UnexpectPeerId);
        }

        let raddrs = identify
            .listenAddrs
            .into_iter()
            .map(|buf| Multiaddr::try_from(buf).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?;

        switch.route_table_put(peer_id, &raddrs).await?;

        Ok(())
    }
}
