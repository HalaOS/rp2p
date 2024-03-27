//! A [`RouteTable`] implementation for test purposes.

use std::{
    collections::{HashMap, HashSet},
    io,
};

use async_trait::async_trait;
use futures::stream;
use rasi_ext::utils::{AsyncLockable, AsyncSpinMutex};
use rp2p_core::{multiaddr::Multiaddr, BoxMultiaddrIterator, PeerId, RouteTable};

/// A [`RouteTable`] implementation that stores all data in memory.
#[derive(Default)]
pub struct MemoryRouteTable(AsyncSpinMutex<HashMap<PeerId, HashSet<Multiaddr>>>);

#[async_trait]
impl RouteTable for MemoryRouteTable {
    /// Add addresses to route table by `peer_id`.
    async fn put(&self, peer_id: PeerId, addrs: &[Multiaddr]) -> io::Result<()> {
        let mut map = self.0.lock().await;

        if let Some(peer_addrs) = map.get_mut(&peer_id) {
            peer_addrs.extend(addrs.iter().cloned());
        } else {
            map.insert(peer_id, addrs.iter().cloned().collect::<HashSet<_>>());
        }

        Ok(())
    }
    /// Get peer's listener address.
    ///
    /// On success, returns a asynchronous `Stream` of listener's addresses.
    async fn get(&self, peer_id: &PeerId) -> io::Result<Option<BoxMultiaddrIterator>> {
        let map = self.0.lock().await;

        let addrs = map
            .get(&peer_id)
            .map(|h| h.iter().cloned().collect::<Vec<_>>());

        Ok(addrs.map(|addrs| {
            let iter: BoxMultiaddrIterator = Box::new(stream::iter(addrs));

            iter
        }))
    }

    /// Delete `addrs` from route table by `peer_id`.
    async fn delete(&self, peer_id: &PeerId, addrs: &[Multiaddr]) -> io::Result<()> {
        let mut map = self.0.lock().await;

        if let Some(peer_addrs) = map.get_mut(&peer_id) {
            addrs.iter().for_each(|addr| {
                peer_addrs.remove(addr);
            });
        }

        Ok(())
    }

    /// Delete all route information from route table by `peer_id`.
    async fn delete_all(&self, peer_id: &PeerId) -> io::Result<()> {
        let mut map = self.0.lock().await;
        map.remove(&peer_id);

        Ok(())
    }
}
