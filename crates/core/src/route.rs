use std::io;

use async_trait::async_trait;
use futures::Stream;
use identity::PeerId;
use multiaddr::Multiaddr;

/// The alias of type [`Box<dyn MultiaddrIterator>`]
pub type BoxMultiaddrIterator = Box<dyn MultiaddrIterator>;

/// The alias of type [`Box<dyn RouteTable>`]
pub type BoxRouteTable = Box<dyn RouteTable>;

/// The `RouteTable` plugin provide the ability that `Switch` can get/set/update the peer route information.
#[async_trait]
pub trait RouteTable: Sync + Send + Unpin {
    /// Add addresses to route table by `peer_id`.
    async fn put(&self, peer_id: PeerId, addrs: &[Multiaddr]) -> io::Result<()>;
    /// Get peer's listener address.
    ///
    /// On success, returns a asynchronous [`Stream`] of listener's addresses.
    async fn get(&self, peer_id: &PeerId) -> io::Result<Option<BoxMultiaddrIterator>>;

    /// Delete `addrs` from route table by `peer_id`.
    async fn delete(&self, peer_id: &PeerId, addrs: &[Multiaddr]) -> io::Result<()>;

    /// Delete all route information from route table by `peer_id`.
    async fn delete_all(&self, peer_id: &PeerId) -> io::Result<()>;
}

/// A async iterator of multiaddr.
pub trait MultiaddrIterator: Stream<Item = Multiaddr> + Sync + Sync + Unpin {}
