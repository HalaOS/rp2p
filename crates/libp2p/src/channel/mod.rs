mod quic;
mod tcp;
mod tls;

// pub use quic::*;
pub use tcp::*;
pub use tls::*;

mod utils;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rasi::{executor::spawn, utils::cancelable_would_block};
    use rasi_default::{executor::register_futures_executor, net::register_mio_network};

    use crate::{
        plugin::keypair::memory::MemoryKeyProvider, KeypairProvider, SecureUpgrade, Transport,
    };

    use super::{tcp::TcpTransport, tls::TlsSecureUpgrade};

    #[futures_test::test]
    async fn test_tls() {
        _ = pretty_env_logger::try_init();
        register_mio_network();
        register_futures_executor().unwrap();

        let transport: Arc<Box<dyn Transport>> = Arc::new(Box::new(TcpTransport::default()));
        let secure_upgrade: Arc<Box<dyn SecureUpgrade>> =
            Arc::new(Box::new(TlsSecureUpgrade::default()));

        let keypair: Arc<Box<dyn KeypairProvider>> =
            Arc::new(Box::new(MemoryKeyProvider::random()));

        let laddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let server = cancelable_would_block(|cx| transport.bind(cx, keypair.clone(), &laddr))
            .await
            .unwrap();

        let raddr = transport.listener_local_addr(&server).unwrap();

        let transport_server = transport.clone();

        let keypair_server: Arc<Box<dyn KeypairProvider>> =
            Arc::new(Box::new(MemoryKeyProvider::random()));

        let secure_upgrade_server = secure_upgrade.clone();

        spawn(async move {
            let stream_handle = Arc::new(
                cancelable_would_block(|cx| transport_server.accept(cx, &server))
                    .await
                    .unwrap(),
            );

            let secure_handle = cancelable_would_block(|cx| {
                secure_upgrade_server.upgrade_server(
                    cx,
                    stream_handle.clone(),
                    transport_server.clone(),
                    keypair_server.clone(),
                )
            })
            .await
            .unwrap();

            cancelable_would_block(|cx| secure_upgrade_server.handshake(cx, &secure_handle))
                .await
                .unwrap();

            log::trace!("handshake :{:?}", secure_handle);
        });

        let stream_handle = Arc::new(
            cancelable_would_block(|cx| transport.connect(cx, &raddr, keypair.clone()))
                .await
                .unwrap(),
        );

        let secure_handle = cancelable_would_block(|cx| {
            secure_upgrade.upgrade_client(
                cx,
                stream_handle.clone(),
                transport.clone(),
                keypair.clone(),
            )
        })
        .await
        .unwrap();

        cancelable_would_block(|cx| secure_upgrade.handshake(cx, &secure_handle))
            .await
            .unwrap();
    }
}
