use std::collections::{HashMap, HashSet};

use identity::PeerId;
use multiaddr::Multiaddr;
use rasi::syscall::CancelablePoll;
use rasi_ext::utils::{Lockable, SpinMutex};

use super::{KeyPair, Neighbors};

#[derive(Default)]
pub struct DefaultKeyPair;

impl KeyPair for DefaultKeyPair {}

#[derive(Default)]
pub struct DefaultNeighbors(SpinMutex<HashMap<PeerId, HashSet<Multiaddr>>>);

impl Neighbors for DefaultNeighbors {
    fn neighbors_put(
        &self,
        _cx: &mut std::task::Context<'_>,
        peer_id: identity::PeerId,
        raddrs: &[multiaddr::Multiaddr],
    ) -> rasi::syscall::CancelablePoll<std::io::Result<()>> {
        let mut table = self.0.lock();
        if let Some(adds) = table.get_mut(&peer_id) {
            for raddr in raddrs {
                adds.insert(raddr.clone());
            }
        } else {
            let mut addrs = HashSet::new();

            for raddr in raddrs {
                addrs.insert(raddr.clone());
            }

            table.insert(peer_id, addrs);
        }

        CancelablePoll::Ready(Ok(()))
    }

    fn neighbors_get(
        &self,
        _cx: &mut std::task::Context<'_>,
        peer_id: &identity::PeerId,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<Vec<multiaddr::Multiaddr>>> {
        let addrs = self
            .0
            .lock()
            .get(peer_id)
            .map(|addrs| addrs.iter().cloned().collect::<Vec<_>>())
            .unwrap_or(vec![]);

        CancelablePoll::Ready(Ok(addrs))
    }

    fn neighbors_delete(
        &self,
        _cx: &mut std::task::Context<'_>,
        peer_id: &identity::PeerId,
        raddrs: &[multiaddr::Multiaddr],
    ) -> rasi::syscall::CancelablePoll<std::io::Result<()>> {
        if let Some(adds) = self.0.lock().get_mut(&peer_id) {
            for raddr in raddrs {
                adds.remove(raddr);
            }
        }

        CancelablePoll::Ready(Ok(()))
    }

    fn neighbors_delete_all(
        &self,
        _cx: &mut std::task::Context<'_>,
        peer_id: &identity::PeerId,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<()>> {
        self.0.lock().remove(peer_id);
        CancelablePoll::Ready(Ok(()))
    }
}
