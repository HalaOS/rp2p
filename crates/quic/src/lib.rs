use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use rasi_ext::net::{
    quic::{self, Config, QuicConn, QuicConnector, QuicListener},
    tls::{
        ec, pkey,
        ssl::{SslAlert, SslContextBuilder, SslMethod, SslVerifyError, SslVerifyMode, SslVersion},
    },
};
use rp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    BoxConnection, BoxHostKey, BoxListener, BoxStream, Connection, HostKey, Listener, PeerId,
    PublicKey, Transport,
};

fn to_sockaddr(addr: &Multiaddr) -> Option<SocketAddr> {
    let mut iter = addr.iter();

    let ip = match iter.next()? {
        Protocol::Ip4(ip) => IpAddr::from(ip),
        Protocol::Ip6(ip) => IpAddr::from(ip),
        _ => return None,
    };

    let next = iter.next()?;

    match next {
        Protocol::Tcp(port) | Protocol::Udp(port) => {
            return Some(SocketAddr::new(ip, port));
        }
        _ => {}
    }

    None
}

#[derive(Default)]
pub struct QuicTransport;

impl QuicTransport {
    /// Create new tcp transport with provided [`yamux::Config`]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Transport for QuicTransport {
    /// Test if this transport support the `laddr`.
    fn multiaddr_hint(&self, laddr: &Multiaddr) -> bool {
        let stack = laddr.protocol_stack().collect::<Vec<_>>();

        if stack.len() > 2 {
            if stack[1] == "udp" && stack[2] == "quic-v1" {
                return true;
            }
        }

        return false;
    }
    /// Create a server side socket and bind it on `laddr`.
    async fn bind(&self, host_key: Arc<BoxHostKey>, laddr: &Multiaddr) -> io::Result<BoxListener> {
        let quic_config = create_quic_config(&**host_key).await?;

        let laddrs =
            to_sockaddr(laddr).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid laddr"))?;

        let listener = QuicListener::bind(laddrs, quic_config).await?;

        let laddr = listener.local_addrs().next().unwrap().clone();

        Ok(Box::new(P2pQuicListener::new(listener, laddr)))
    }

    /// Create a client socket and establish one [`Connection`](Connection) to `raddr`.
    async fn connect(
        &self,
        host_key: Arc<BoxHostKey>,
        raddr: &Multiaddr,
    ) -> io::Result<BoxConnection> {
        let mut quic_config = create_quic_config(&**host_key).await?;

        let raddr =
            to_sockaddr(raddr).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid laddr"))?;

        let laddr = if raddr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let connector = QuicConnector::new(None, laddr, raddr, &mut quic_config).await?;

        let laddr = connector.udp_group.local_addrs().next().unwrap().clone();

        let conn = connector.connect().await?;

        let cert = conn.to_inner_conn().await.peer_cert().unwrap().to_vec();

        let public_key = rp2p_x509::verify(cert)?;

        Ok(Box::new(P2pQuicConn::new(laddr, raddr, conn, public_key)))
    }
}

struct P2pQuicListener {
    laddr: SocketAddr,
    listener: QuicListener,
}

impl P2pQuicListener {
    fn new(listener: QuicListener, laddr: SocketAddr) -> Self {
        Self { laddr, listener }
    }
}

#[async_trait]
impl Listener for P2pQuicListener {
    async fn accept(&self) -> io::Result<BoxConnection> {
        let conn = self.listener.accept().await.ok_or(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "Quic server shutdown.",
        ))?;

        let cert = conn.to_inner_conn().await.peer_cert().unwrap().to_vec();

        let public_key = rp2p_x509::verify(cert)?;

        let raddr = conn
            .to_inner_conn()
            .await
            .paths_iter(self.laddr)
            .next()
            .unwrap();

        Ok(Box::new(P2pQuicConn::new(
            self.laddr, raddr, conn, public_key,
        )))
    }

    /// Returns local bind address.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out which port was
    /// actually bound.
    fn local_addr(&self) -> io::Result<Multiaddr> {
        let mut addr = Multiaddr::from(self.laddr.ip());
        addr.push(Protocol::Udp(self.laddr.port()));
        addr.push(Protocol::QuicV1);

        Ok(addr)
    }
}

struct P2pQuicConn {
    laddr: SocketAddr,
    raddr: SocketAddr,
    conn: QuicConn,
    public_key: PublicKey,
}

impl P2pQuicConn {
    fn new(laddr: SocketAddr, raddr: SocketAddr, conn: QuicConn, public_key: PublicKey) -> Self {
        Self {
            laddr,
            raddr,
            conn,
            public_key,
        }
    }
}

#[async_trait]
impl Connection for P2pQuicConn {
    /// Returns local bind address.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out which port was
    /// actually bound.
    fn local_addr(&self) -> io::Result<Multiaddr> {
        let mut addr = Multiaddr::from(self.laddr.ip());
        addr.push(Protocol::Tcp(self.laddr.port()));
        addr.push(Protocol::QuicV1);

        Ok(addr)
    }

    /// Returns the remote address that this connection is connected to.
    fn peer_addr(&self) -> io::Result<Multiaddr> {
        let mut addr = Multiaddr::from(self.raddr.ip());
        addr.push(Protocol::Tcp(self.raddr.port()));
        addr.push(Protocol::QuicV1);

        Ok(addr)
    }

    /// Return peer's id obtained from secure layer peer's public key.
    fn peer_id(&self) -> io::Result<PeerId> {
        Ok(self.public_key.to_peer_id())
    }

    /// Return the secure layer peer's public key.
    fn public_key(&self) -> io::Result<PublicKey> {
        Ok(self.public_key.clone())
    }

    /// Open a outbound stream for reading/writing via this connection.
    async fn open(&self) -> io::Result<BoxStream> {
        Ok(Box::new(self.conn.stream_open(true).await?))
    }

    /// Accept newly incoming stream for reading/writing.
    ///
    /// If the connection is dropping or has been dropped, this function will returns `None`.
    async fn accept(&self) -> io::Result<BoxStream> {
        let stream = self.conn.stream_accept().await.ok_or(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "Quic conn closed",
        ))?;

        Ok(Box::new(stream))
    }

    /// Attempt to close this connection.
    async fn close(&self) -> io::Result<()> {
        self.conn.close().await
    }
}

async fn create_quic_config(host_key: &dyn HostKey) -> io::Result<Config> {
    let (cert, pk) = rp2p_x509::generate(host_key).await?;

    let cert = rasi_ext::net::tls::x509::X509::from_der(&cert)?;

    let pk = pkey::PKey::from_ec_key(ec::EcKey::private_key_from_der(&pk)?)?;

    let mut ssl_context_builder = SslContextBuilder::new(SslMethod::tls())?;

    ssl_context_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    ssl_context_builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;

    ssl_context_builder.set_certificate(&cert)?;

    ssl_context_builder.set_private_key(&pk)?;

    ssl_context_builder.check_private_key()?;

    ssl_context_builder.set_custom_verify_callback(
        SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
        |ssl| {
            let cert = ssl
                .certificate()
                .ok_or(SslVerifyError::Invalid(SslAlert::CERTIFICATE_REQUIRED))?;

            let cert = cert
                .to_der()
                .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;

            let peer_id = rp2p_x509::verify(cert)
                .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?
                .to_peer_id();

            log::trace!("ssl_server: verified peer={}", peer_id);

            Ok(())
        },
    );

    let mut config = quic::Config::new_with_ssl_cx_builder(ssl_context_builder);

    config.verify_peer(true);

    config.set_application_protos(&[b"libp2p"]).unwrap();

    Ok(config)
}

#[cfg(test)]
mod tests {

    use rasi::{
        executor::spawn,
        io::{AsyncReadExt, AsyncWriteExt},
    };
    use rasi_default::{
        executor::register_futures_executor, net::register_mio_network, time::register_mio_timer,
    };
    use rp2p_core::{HostKey, Keypair, PublicKey};

    use super::*;

    struct MockHostKey(Keypair);

    impl Default for MockHostKey {
        fn default() -> Self {
            Self(Keypair::generate_ed25519())
        }
    }

    #[async_trait]
    impl HostKey for MockHostKey {
        /// Get the public key of host keypair.
        async fn public_key(&self) -> io::Result<PublicKey> {
            Ok(self.0.public())
        }

        /// Sign the unhashed data using the private key.
        async fn sign(&self, data: &[u8]) -> io::Result<Vec<u8>> {
            Ok(self.0.sign(data).unwrap())
        }
    }

    #[futures_test::test]
    async fn test_tls() {
        register_mio_network();
        register_mio_timer();
        register_futures_executor().unwrap();

        // pretty_env_logger::init();

        let transport = QuicTransport::default();

        let server_host_key: Arc<BoxHostKey> = Arc::new(Box::new(MockHostKey::default()));

        let laddr = "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap();

        let listener = transport
            .bind(server_host_key.clone(), &laddr)
            .await
            .unwrap();

        let laddr = listener.local_addr().unwrap();

        spawn(async move {
            let conn = listener.accept().await.unwrap();

            log::info!(
                "server {:?} => {:?}",
                conn.local_addr().unwrap(),
                conn.peer_addr().unwrap()
            );

            log::trace!("server accept next");

            loop {
                let mut stream = conn.accept().await.unwrap();

                log::trace!("server accept one");

                let mut buf = vec![0; 32];

                let read_size = stream.read(&mut buf).await.unwrap();

                log::trace!("server read");

                assert_eq!(&buf[..read_size], b"hello world");

                stream.write_all(&buf[..read_size]).await.unwrap();
            }
        });

        let client_host_key: Arc<BoxHostKey> = Arc::new(Box::new(MockHostKey::default()));

        let conn = transport.connect(client_host_key, &laddr).await.unwrap();

        log::info!(
            "client {:?} => {:?}",
            conn.local_addr().unwrap(),
            conn.peer_addr().unwrap()
        );

        let mut stream = conn.open().await.unwrap();

        stream.write_all(b"hello world").await.unwrap();

        log::trace!("client write");

        stream.flush().await.unwrap();

        let mut buf = vec![0; 32];

        let read_size = stream.read(&mut buf).await.unwrap();

        assert_eq!(&buf[..read_size], b"hello world");
    }
}
