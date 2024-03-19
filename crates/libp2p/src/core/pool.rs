use std::collections::HashMap;

use identity::PeerId;
use rand::{seq::IteratorRandom, thread_rng};
use rasi_ext::utils::{AsyncLockable, AsyncSpinMutex};

use super::P2pConn;

/// The connection pool for peers.
#[derive(Default)]
pub struct ConnPoolOfPeers {
    pools: AsyncSpinMutex<HashMap<PeerId, Vec<P2pConn>>>,
}

impl ConnPoolOfPeers {
    /// Put a [`P2pConn`] into peer's pool
    pub async fn put(&self, conn: P2pConn) {
        let peer_id = conn.peer_id();

        let mut pools = self.pools.lock().await;

        if let Some(peer_pool) = pools.get_mut(&peer_id) {
            peer_pool.push(conn);
        } else {
            pools.insert(peer_id.clone(), vec![conn]);
        }
    }

    /// Random select one connection from the peer pool.
    ///
    /// Returns [`None`], if there are no active connections.
    pub async fn get(&self, peer_id: &PeerId) -> Option<P2pConn> {
        let pools = self.pools.lock().await;

        if let Some(peer_pool) = pools.get(&peer_id) {
            peer_pool
                .iter()
                .choose(&mut thread_rng())
                .map(|conn| conn.clone())
        } else {
            None
        }
    }

    pub async fn delete(&self, peer_id: &PeerId, dropping: &[P2pConn]) {
        let mut pools = self.pools.lock().await;

        if let Some(mut peer_pool) = pools.remove(&peer_id) {
            peer_pool.sort_by(|lhs, rhs| {
                lhs.to_handle()
                    .as_ref()
                    .partial_cmp(rhs.to_handle().as_ref())
                    .unwrap()
            });

            for conn in dropping {
                if let Ok(index) = peer_pool.binary_search_by(|c| {
                    c.to_handle()
                        .as_ref()
                        .partial_cmp(conn.to_handle().as_ref())
                        .unwrap()
                }) {
                    peer_pool.remove(index);
                }
            }
        }
    }
}
