use std::io;

use async_trait::async_trait;

use crate::P2pConn;

use identity::PeerId;

/// Type alias of [`Box<dyn ConnPool>`]
pub type BoxConnPool = Box<dyn ConnPool>;

/// The `ConnPool` plugin provides the ability for switch to cache transport layer connections.
///
/// By design, the liveness check is the `ConnPool`'s responsibility,
/// so the plugin must implement and perform the `/ipfs/ping/1.0.0` protocol.
#[async_trait]
pub trait ConnPool: Sync + Send + Unpin {
    /// Cache one transport layer connection.
    async fn cache(&self, conn: P2pConn) -> io::Result<()>;

    /// Try open one outbound stream via connection by `raddr` in this pool.
    async fn get(&self, peer_id: &PeerId) -> io::Result<Option<P2pConn>>;

    /// Remove one connection from cache pool
    async fn remove(&self, conn: P2pConn) -> io::Result<()>;
}
