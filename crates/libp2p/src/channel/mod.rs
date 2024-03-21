pub mod quic;
pub mod tcp;
pub mod tls;

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
        register_mio_network();
        register_futures_executor().unwrap();

        let transport: Arc<Box<dyn Transport>> = Arc::new(Box::new(TcpTransport::default()));
        let secure_upgrade: Arc<Box<dyn SecureUpgrade>> =
            Arc::new(Box::new(TlsSecureUpgrade::default()));

        let keypair: Arc<Box<dyn KeypairProvider>> =
            Arc::new(Box::new(MemoryKeyProvider::random()));

        let laddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

        let server = cancelable_would_block(|cx, pending| {
            transport.bind(cx, keypair.clone(), &laddr, pending)
        })
        .await
        .unwrap();

        let raddr = transport.listener_local_addr(&server).unwrap();

        let transport_server = transport.clone();

        let keypair_server = keypair.clone();

        let secure_upgrade_server = secure_upgrade.clone();

        spawn(async move {
            let stream_handle =
                cancelable_would_block(|cx, pending| transport_server.accept(cx, &server, pending))
                    .await
                    .unwrap();

            let secure_handle = secure_upgrade_server
                .upgrade_server(
                    stream_handle,
                    transport_server.clone(),
                    keypair_server.clone(),
                )
                .unwrap();

            cancelable_would_block(|cx, pending| {
                secure_upgrade_server.handshake(cx, &secure_handle, pending)
            })
            .await
            .unwrap();
        });

        let stream_handle = cancelable_would_block(|cx, pending| {
            transport.connect(cx, &raddr, keypair.clone(), pending)
        })
        .await
        .unwrap();

        let secure_handle = secure_upgrade
            .upgrade_server(stream_handle, transport.clone(), keypair.clone())
            .unwrap();

        cancelable_would_block(|cx, pending| secure_upgrade.handshake(cx, &secure_handle, pending))
            .await
            .unwrap();
    }
}
