use std::{
    collections::{HashMap, HashSet},
    io,
    sync::Arc,
    task::Context,
    time::Duration,
};

use futures::AsyncReadExt;
use identity::PeerId;

use rand::{seq::IteratorRandom, thread_rng, RngCore};
use rasi::{
    executor::spawn,
    poll_cancelable,
    syscall::{CancelablePoll, PendingHandle},
    time::sleep,
};
use rasi_ext::utils::{AsyncLockable, AsyncSpinMutex};

use crate::{
    errors::{P2pError, Result},
    ConnPool, P2pConn,
};

use rasi::io::AsyncWriteExt;

#[derive(Clone)]
pub struct AutoPingConnPool {
    ping_duration: Option<Duration>,
    pools: Arc<AsyncSpinMutex<HashMap<PeerId, HashSet<P2pConn>>>>,
}

impl Default for AutoPingConnPool {
    fn default() -> Self {
        Self {
            ping_duration: Some(Duration::from_secs(60)),
            pools: Default::default(),
        }
    }
}

impl AutoPingConnPool {
    /// Create new connection pool, with provided `ping_duration`.
    ///
    /// If `ping_duration` is None, the auto ping test process will not start.
    pub fn new(ping_duration: Option<Duration>) -> Self {
        Self {
            ping_duration,
            ..Default::default()
        }
    }

    async fn put(&self, conn: P2pConn) {
        let mut pools = self.pools.lock().await;

        let peer_id = conn.peer_id();

        if let Some(peer_pool) = pools.get_mut(&peer_id) {
            peer_pool.insert(conn.clone());
        } else {
            let mut peer_pool = HashSet::new();

            peer_pool.insert(conn.clone());

            pools.insert(peer_id, peer_pool);
        }

        if !conn.is_server() && self.ping_duration.is_some() {
            let this = self.clone();
            let ping_duration = self.ping_duration.unwrap();

            spawn(async move {
                this.ping_loop(conn, ping_duration).await;
            });
        }
    }

    async fn get(&self, peer_id: &PeerId) -> Option<P2pConn> {
        let mut pools = self.pools.lock().await;

        if let Some(peer_pool) = pools.get_mut(&peer_id) {
            Some(peer_pool.iter().choose(&mut thread_rng()).cloned().unwrap())
        } else {
            None
        }
    }

    async fn remove(&self, conn: P2pConn) {
        let mut pools = self.pools.lock().await;

        if let Some(peer_pool) = pools.get_mut(&conn.peer_id()) {
            peer_pool.remove(&conn);
        }
    }

    async fn ping_loop(&self, conn: P2pConn, duration: Duration) {
        match Self::ping_loop_inner(conn.clone(), duration).await {
            Err(err) => {
                log::error!(
                    "connection raddr={}, ping loop stop with error: {}",
                    conn.peer_addr(),
                    err
                );
            }
            _ => {
                log::error!("connection raddr={}, ping loop stop", conn.peer_addr(),);
            }
        }

        self.remove(conn).await;
    }

    async fn ping_loop_inner(conn: P2pConn, duration: Duration) -> Result<()> {
        let mut stream = conn.open(["/ipfs/ping/1.0.0".try_into().unwrap()]).await?;

        loop {
            let mut buf = vec![0u8; 32];

            rand::thread_rng().fill_bytes(&mut buf);

            stream.write_all(&buf).await?;

            let mut resp = vec![0u8; 32];

            stream.read_exact(&mut resp).await?;

            if resp != buf {
                return Err(P2pError::Ping);
            }

            sleep(duration).await;
        }
    }
}

impl ConnPool for AutoPingConnPool {
    fn put(
        &self,
        cx: &mut Context<'_>,
        conn: crate::P2pConn,
        cancel_handle: Option<PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<()>> {
        poll_cancelable!(Put, cx, cancel_handle, || async {
            Ok(self.put(conn).await)
        })
    }

    fn get<'a>(
        &self,
        cx: &'a mut Context<'_>,
        peer_id: &'a identity::PeerId,
        cancel_handle: Option<PendingHandle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<Option<crate::P2pConn>>> {
        poll_cancelable!(Get, cx, cancel_handle, || async {
            Ok(self.get(peer_id).await)
        })
    }

    fn remove<'a>(
        &'a self,
        cx: &'a mut Context<'_>,
        conn: P2pConn,
        cancel_handle: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<()>> {
        poll_cancelable!(Remove, cx, cancel_handle, || async {
            Ok(self.remove(conn).await)
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use futures_test::task::noop_context;
    use identity::PeerId;
    use rasi::{poll_cancelable, syscall::CancelablePoll, utils::cancelable_would_block};
    use rasi_ext::utils::{AsyncLockable, AsyncSpinMutex};

    use crate::ConnPool;

    use super::AutoPingConnPool;

    #[futures_test::test]
    async fn test_auto_ping_pool() {
        let pool: Box<dyn ConnPool> = Box::new(AutoPingConnPool::default());

        let peer_id = PeerId::random();

        let conn =
            cancelable_would_block(|cx, cancel_handle| pool.get(cx, &peer_id, cancel_handle))
                .await
                .unwrap();

        assert!(conn.is_none());
    }

    #[futures_test::test]
    async fn test_cancelable() {
        let mutex = AsyncSpinMutex::new(());

        let pending = None;

        let counter = Arc::new(AtomicUsize::new(0));

        fn lock(
            pending: Option<rasi::syscall::PendingHandle>,
            mutex: &AsyncSpinMutex<()>,
            counter: Arc<AtomicUsize>,
        ) -> CancelablePoll<()> {
            poll_cancelable!(Test, &mut noop_context(), pending, || async {
                counter.fetch_add(1, Ordering::Relaxed);
                let _ = mutex.lock().await;
            })
        }

        let pending = {
            let _guard = mutex.lock().await;

            let poll = lock(pending, &mutex, counter.clone());

            assert!(poll.is_pending());

            poll.into_pending()
        };

        let poll = lock(pending, &mutex, counter.clone());

        assert!(poll.is_ready());

        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
}
