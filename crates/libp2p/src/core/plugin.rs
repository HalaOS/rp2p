use std::{io, task::Context};

use identity::{PeerId, PublicKey};
use multiaddr::Multiaddr;
use rasi::syscall::{CancelablePoll, Handle};

use super::P2pConn;

/// The service that provide the functions to access the `Switch`'s security keypair.
pub trait KeypairProvider: Sync + Send {
    fn public_key(&self, cx: &mut Context<'_>) -> CancelablePoll<io::Result<PublicKey>>;
}

/// Neighbors is a set of libp2p peers, that can be directly connected by switch.
///
/// This trait provides a set of functions to get/update/delete the peer's route information in the `Neighbors`.
pub trait NeighborStorage: Sync + Send {
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

/// A service that provide ability of caching peer connections.
pub trait ConnPool: Sync + Send {
    /// Put one connection into `peer's connection pool`.
    fn put(
        &self,
        cx: &mut Context<'_>,
        conn: P2pConn,
        cancel_handle: Option<Handle>,
    ) -> CancelablePoll<io::Result<()>>;

    fn get(
        &self,
        cx: &mut Context<'_>,
        peer_id: &PeerId,
        cancel_handle: Option<Handle>,
    ) -> CancelablePoll<io::Result<Option<P2pConn>>>;
}
