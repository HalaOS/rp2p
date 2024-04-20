use std::{
    collections::{HashMap, HashSet},
    io,
    time::Duration,
};

use async_trait::async_trait;
use futures::{AsyncReadExt, AsyncWriteExt};
use rand::{seq::IteratorRandom, thread_rng, Rng};
use rasi::{
    executor::spawn,
    time::{sleep, TimeoutExt},
};
use rasi_ext::utils::{AsyncLockable, AsyncSpinMutex};
use rp2p_core::{ConnPool, P2pConn, PeerId};

/// A [`ConnPool`] implementation with auto liveness check support.
pub struct ConnPoolWithPing {
    ping_duration: Duration,
    peers: AsyncSpinMutex<HashMap<PeerId, HashSet<P2pConn>>>,
}

impl Default for ConnPoolWithPing {
    fn default() -> Self {
        Self {
            ping_duration: Duration::from_secs(24),
            peers: Default::default(),
        }
    }
}

#[async_trait]
impl ConnPool for ConnPoolWithPing {
    /// Cache one transport layer connection.
    async fn cache(&self, conn: P2pConn) -> io::Result<()> {
        let peer_id = conn.peer_id()?;

        let mut peers = self.peers.lock().await;

        if let Some(conns) = peers.get_mut(&peer_id) {
            conns.insert(conn.clone());
        } else {
            let conns = [conn.clone()].into_iter().collect::<HashSet<_>>();

            peers.insert(peer_id, conns);
        }

        spawn(ping_loop(conn, self.ping_duration));

        Ok(())
    }

    /// Try open one outbound stream via connection by `raddr` in this pool.
    async fn get(&self, peer_id: &PeerId) -> io::Result<Option<P2pConn>> {
        let peers = self.peers.lock().await;

        let conn = peers
            .get(&peer_id)
            .map(|conns| conns.iter().choose(&mut thread_rng()).cloned().unwrap());

        Ok(conn)
    }

    /// Remove one connection from cache pool
    async fn remove(&self, conn: P2pConn) -> io::Result<()> {
        let peer_id = conn.peer_id()?;

        let mut peers = self.peers.lock().await;

        if let Some(conns) = peers.get_mut(&peer_id) {
            conns.remove(&conn);
        }

        Ok(())
    }
}

async fn ping_loop(mut conn: P2pConn, ping_interval: Duration) {
    loop {
        if let Err(err) = ping_once(&mut conn, ping_interval).await {
            log::error!("{:?} ping with error: {}", conn, err);
            _ = conn.close().await;
            break;
        }

        sleep(ping_interval).await;
    }
}

async fn ping_once(conn: &mut P2pConn, ping_interval: Duration) -> io::Result<()> {
    let mut stream = conn.open(["/ipfs/ping/1.0.0"]).await?;

    let buf: [u8; 31] = thread_rng().gen();

    let mut payload_len = unsigned_varint::encode::usize_buffer();

    stream
        .write_all(unsigned_varint::encode::usize(32, &mut payload_len))
        .await?;

    stream.write_all(&buf).await?;

    let echo = async move {
        let body_len = unsigned_varint::aio::read_usize(&mut stream)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

        log::trace!("recv /ipfs/ping/1.0.0 payload len {}", body_len);

        if body_len != 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Recieved invalid ping echo",
            ));
        }

        let mut resp = vec![0; 31];

        stream.read_exact(&mut resp).await?;

        if resp != buf {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Recieved invalid ping echo",
            ));
        }

        log::trace!("recv /ipfs/ping/1.0.0 echo matched");

        Ok(())
    };

    echo.timeout(ping_interval).await.ok_or(io::Error::new(
        io::ErrorKind::TimedOut,
        "read ping echo timeout",
    ))??;

    Ok(())
}
