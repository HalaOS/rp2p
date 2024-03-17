use std::{io, task::Context};

use identity::PeerId;
use multiaddr::Multiaddr;
use rasi::syscall::CancelablePoll;

/// Neighbors is a set of libp2p peers, that can be directly connected by switch.
///
/// This trait provides a set of functions to get/update/delete the peer's route information in the `Neighbors`.
pub trait Neighbors {
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

#[derive(Default)]
pub struct MemoryNeighbors {}

#[allow(unused)]
impl Neighbors for MemoryNeighbors {
    fn neighbors_put(
        &self,
        cx: &mut Context<'_>,
        peer_id: PeerId,
        raddrs: &[Multiaddr],
    ) -> CancelablePoll<io::Result<()>> {
        todo!()
    }

    fn neighbors_get(
        &self,
        cx: &mut Context<'_>,
        peer_id: &PeerId,
    ) -> CancelablePoll<io::Result<Vec<Multiaddr>>> {
        todo!()
    }

    fn neighbors_delete(
        &self,
        cx: &mut Context<'_>,
        peer_id: &PeerId,
        raddrs: &[Multiaddr],
    ) -> CancelablePoll<io::Result<()>> {
        todo!()
    }

    fn neighbors_delete_all(
        &self,
        cx: &mut Context<'_>,
        peer_id: &PeerId,
    ) -> CancelablePoll<io::Result<()>> {
        todo!()
    }
}
