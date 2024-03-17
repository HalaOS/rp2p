use std::{collections::HashMap, sync::Arc};

use identity::PeerId;
use rasi::{syscall::Handle, utils::cancelable_would_block};
use rasi_ext::utils::{AsyncLockable, AsyncSpinMutex};

use super::{Multiplexing, SwitchHandle};

/// libp2p uses muxing streams to transfer data,
/// so in most cases it is not necessary to create new transport layer connections.
/// A new outbound stream is created from an existing mux connecton,
/// regardless of whether the mux connection is inbound or outbound.
#[derive(Default)]
pub(crate) struct MuxingPool {
    peers: AsyncSpinMutex<HashMap<PeerId, Vec<Arc<Handle>>>>,
}

impl MuxingPool {
    /// Input new muxing connection into pool.
    pub async fn put(&self, peer_id: &PeerId, connection_handle: Arc<Handle>) {
        let mut peers = self.peers.lock().await;

        if let Some(peer_pool) = peers.get_mut(peer_id) {
            peer_pool.push(connection_handle);
        } else {
            peers.insert(peer_id.clone(), vec![connection_handle]);
        }
    }

    /// Try to start a new muxing stream from a muxing connection in this pool.
    pub async fn connect(
        &self,
        muxing: &dyn Multiplexing,
        peer_id: &PeerId,
    ) -> Option<SwitchHandle> {
        let conns = {
            let peers = self.peers.lock().await;

            peers.get(&peer_id).map(|conns| conns.clone())
        };

        if let Some(conns) = conns {
            let mut dropping = vec![];

            for connection_handle in conns {
                match cancelable_would_block(|cx| muxing.open(cx, &connection_handle)).await {
                    Ok(stream_handle) => {
                        self.close_conns(peer_id, &dropping).await;

                        return Some(SwitchHandle::MuxingUpgrade {
                            stream_handle,
                            connection_handle,
                        });
                    }
                    Err(err) => {
                        log::error!(
                            "Muxing pool: open new stream of {} with error, {}",
                            peer_id,
                            err
                        );

                        dropping.push(connection_handle);
                    }
                }
            }

            self.close_conns(peer_id, &dropping).await;
        }

        None
    }

    async fn close_conns(&self, peer_id: &PeerId, dropping: &[Arc<Handle>]) {
        let mut peers = self.peers.lock().await;

        if let Some(mut conns) = peers.remove(&peer_id) {
            conns.sort();

            for conn in dropping {
                if let Ok(index) = conns.binary_search(conn) {
                    conns.remove(index);
                }
            }
        }
    }
}
