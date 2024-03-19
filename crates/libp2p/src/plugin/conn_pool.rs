use std::{
    collections::{HashMap, HashSet},
    io,
    pin::Pin,
    sync::Arc,
    task::Context,
};

use futures::Future;
use identity::PeerId;
use rasi::{future::BoxFuture, syscall::Handle};
use rasi_ext::utils::AsyncSpinMutex;

use crate::{ConnPool, P2pConn};

#[derive(Default, Clone)]
pub struct AutoPingConnPool {
    pools: Arc<AsyncSpinMutex<HashMap<PeerId, HashSet<P2pConn>>>>,
}

impl AutoPingConnPool {
    async fn put(self, conn: P2pConn) -> io::Result<()> {
        todo!()
    }

    async fn remove(self, conn: P2pConn) -> io::Result<()> {
        todo!()
    }
}

impl ConnPool for AutoPingConnPool {
    fn put(
        &self,
        cx: &mut Context<'_>,
        conn: crate::P2pConn,
        cancel_handle: Option<Handle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<()>> {
        if let Some(cancel_handle) = cancel_handle {
            cancel_handle.downcast::<BoxFuture<'static, io::Result<()>>>();
        }

        let mut fut: BoxFuture<'static, io::Result<()>> = Box::pin(self.clone().put(conn.clone()));

        match Pin::new(&mut fut).poll(cx) {
            std::task::Poll::Ready(_) => todo!(),
            std::task::Poll::Pending => todo!(),
        }

        todo!()
    }

    fn get(
        &self,
        cx: &mut Context<'_>,
        peer_id: &identity::PeerId,
        cancel_handle: Option<Handle>,
    ) -> rasi::syscall::CancelablePoll<std::io::Result<Option<crate::P2pConn>>> {
        todo!()
    }
}
