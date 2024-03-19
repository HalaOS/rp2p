use std::{
    collections::{HashMap, HashSet},
    io,
    sync::Arc,
    task::Context,
};

use identity::PeerId;
use rand::{seq::IteratorRandom, thread_rng};
use rasi::{
    poll_cancelable,
    syscall::{CancelablePoll, PendingHandle},
};
use rasi_ext::utils::{AsyncLockable, AsyncSpinMutex};

use crate::{ConnPool, P2pConn};

#[derive(Default, Clone)]
pub struct AutoPingConnPool {
    pools: Arc<AsyncSpinMutex<HashMap<PeerId, HashSet<P2pConn>>>>,
}

impl AutoPingConnPool {
    async fn put(&self, conn: P2pConn) -> io::Result<()> {
        let mut pools = self.pools.lock().await;

        let peer_id = conn.peer_id();

        if let Some(peer_pool) = pools.get_mut(&peer_id) {
            peer_pool.insert(conn);
        } else {
            let mut peer_pool = HashSet::new();

            peer_pool.insert(conn);

            pools.insert(peer_id, peer_pool);
        }

        Ok(())
    }

    async fn get(&self, peer_id: &PeerId) -> io::Result<Option<P2pConn>> {
        let mut pools = self.pools.lock().await;

        if let Some(peer_pool) = pools.get_mut(&peer_id) {
            Ok(Some(
                peer_pool.iter().choose(&mut thread_rng()).cloned().unwrap(),
            ))
        } else {
            Ok(None)
        }
    }

    async fn remove(&self, conn: P2pConn) -> io::Result<()> {
        let mut pools = self.pools.lock().await;

        if let Some(peer_pool) = pools.get_mut(&conn.peer_id()) {
            peer_pool.remove(&conn);
        }

        Ok(())
    }
}

impl ConnPool for AutoPingConnPool {
    fn put(
        &self,
        cx: &mut Context<'_>,
        conn: crate::P2pConn,
        cancel_handle: Option<PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<()>> {
        poll_cancelable!(Put, cx, cancel_handle, || self.put(conn))
    }

    fn get<'a>(
        &self,
        cx: &'a mut Context<'_>,
        peer_id: &'a identity::PeerId,
        cancel_handle: Option<PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<Option<crate::P2pConn>>> {
        poll_cancelable!(Get, cx, cancel_handle, || self.get(peer_id))
    }

    fn remove<'a>(
        &'a self,
        cx: &'a mut Context<'_>,
        conn: P2pConn,
        cancel_handle: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<()>> {
        poll_cancelable!(Remove, cx, cancel_handle, || self.remove(conn))
    }
}
