use std::{io, net::Shutdown, sync::Arc, task::Context};

use identity::PeerId;
use multiaddr::Multiaddr;
use rasi::syscall::{CancelablePoll, Handle};

use crate::errors::Result;

use super::SwitchConn;

/// The service that provide the functions to access the `Switch`'s security keypair.
pub trait KeyPair: Sync + Send {}

pub trait IO {
    /// Write data via the `connection handle` to peer.
    ///
    /// On success, returns the written data length.
    fn write(
        &self,
        cx: &mut Context<'_>,
        handle: &Handle,
        buf: &[u8],
    ) -> CancelablePoll<io::Result<usize>>;

    /// Read data via the `connection handle` from peer.
    ///
    /// On success, returns the read data length.
    fn read(
        &self,
        cx: &mut Context<'_>,
        handle: &Handle,
        buf: &mut [u8],
    ) -> CancelablePoll<io::Result<usize>>;

    /// Shuts down the read, write, or both halves of the connection referenced by the [`handle`].
    ///
    /// This method will cause all pending and future I/O on the specified portions to return
    /// immediately with an appropriate value (see the documentation of [`Shutdown`]).
    fn shutdown(&self, handle: &Handle, how: Shutdown) -> io::Result<()>;
}

pub trait Upgrade {
    /// Upgrade a client `SwitchConn` to support more features.
    fn upgrade_client(
        &self,
        source: SwitchConn,
        keypair: Arc<Box<dyn KeyPair>>,
    ) -> io::Result<Handle>;

    /// Upgrade a server `SwitchConn` to support more features.
    fn upgrade_server(
        &self,
        source: SwitchConn,
        keypair: Arc<Box<dyn KeyPair>>,
    ) -> io::Result<Handle>;

    fn handshake(
        &self,
        cx: &mut Context<'_>,
        upgrade_handle: &Handle,
    ) -> CancelablePoll<io::Result<()>>;
}

/// This trait provide the function to fmt handle debug information.
pub trait DebugOfHandle {
    fn fmt_handle(&self, handle: &Handle, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

pub trait Transport: DebugOfHandle + IO + Sync + Send {
    /// Test if this transport exact match the `addr`.
    fn multiaddr_hint(&self, addr: &Multiaddr) -> bool;

    /// Create a server-side listener and bind it on `laddr`.
    fn bind(
        &self,
        cx: &mut Context<'_>,
        keypair: Arc<Box<dyn KeyPair>>,
        laddr: &Multiaddr,
    ) -> CancelablePoll<io::Result<Handle>>;

    /// Accept a newly incoming transport connection.
    fn accept(&self, cx: &mut Context<'_>, handle: &Handle) -> CancelablePoll<io::Result<Handle>>;

    /// Create a transport connection, and connect to `raddr`.
    fn connect(
        &self,
        cx: &mut Context<'_>,
        raddr: &Multiaddr,
        keypair: Arc<Box<dyn KeyPair>>,
    ) -> CancelablePoll<io::Result<Handle>>;
}

pub trait SecureUpgrade: DebugOfHandle + IO + Upgrade + Sync + Send {}

/// A type that upgrade one [`SwitchConn`] to support creating muxing bi-directional data stream.
pub trait MuxingUpgrade: DebugOfHandle + IO + Upgrade + Sync + Send {
    /// Accept a newly incoming muxing stream.
    fn accept(&self, cx: &mut Context<'_>, handle: &Handle) -> CancelablePoll<io::Result<Handle>>;

    /// Create a newly outbound muxing stream.
    fn connect(&self, cx: &mut Context<'_>, handle: &Handle) -> CancelablePoll<io::Result<Handle>>;
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
        keypair: Arc<Box<dyn KeyPair>>,
    ) -> Result<SwitchConn> {
        let switch_conn: SwitchConn = (handle, transport).into();

        let swithc_conn = switch_conn
            .client_secure_upgrade(self.secure_upgrade.clone(), keypair.clone())
            .await?;

        let swithc_conn = swithc_conn
            .client_muxing_upgrade(self.muxing_updrade.clone(), keypair)
            .await?;

        Ok(swithc_conn)
    }

    /// Upgrade a server-side transport connection.
    pub async fn server_conn_upgrade(
        &self,
        handle: Handle,
        transport: Arc<Box<dyn Transport>>,
        keypair: Arc<Box<dyn KeyPair>>,
    ) -> Result<SwitchConn> {
        let switch_conn: SwitchConn = (handle, transport).into();

        let swithc_conn = switch_conn
            .server_secure_upgrade(self.secure_upgrade.clone(), keypair.clone())
            .await?;

        let swithc_conn = swithc_conn
            .server_muxing_upgrade(self.muxing_updrade.clone(), keypair)
            .await?;

        Ok(swithc_conn)
    }
}

///  A channel is a bi-directional network channel maintained by a [`Switch`]
#[derive(Clone)]
pub struct Channel {
    pub(super) transport: Arc<Box<dyn Transport>>,
    pub(super) upgrader: Upgrader,
}

/// Neighbors is a set of libp2p peers, that can be directly connected by switch.
///
/// This trait provides a set of functions to get/update/delete the peer's route information in the `Neighbors`.
pub trait Neighbors: Sync + Send {
    /// manually update a route for the neighbor peer by [`id`](PeerId).
    fn neighbors_put(
        &self,
        cx: &mut Context<'_>,
        peer_id: PeerId,
        raddrs: &[Multiaddr],
    ) -> CancelablePoll<io::Result<()>>;

    /// Returns a copy of route table of one neighbor peer by [`id`](PeerId).
    fn neighbors_get(
        &self,
        cx: &mut Context<'_>,
        peer_id: &PeerId,
    ) -> CancelablePoll<io::Result<Vec<Multiaddr>>>;

    /// remove some route information from neighbor peer by [`id`](PeerId).
    fn neighbors_delete(
        &self,
        cx: &mut Context<'_>,
        peer_id: &PeerId,
        raddrs: &[Multiaddr],
    ) -> CancelablePoll<io::Result<()>>;

    /// Completely, remove the route table of one neighbor peer by [`id`](PeerId).
    fn neighbors_delete_all(
        &self,
        cx: &mut Context<'_>,
        peer_id: &PeerId,
    ) -> CancelablePoll<io::Result<()>>;
}