use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use multistream_select::{dialer_select_proto, listener_select_proto, Version};
use rasi::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use rasi_ext::net::tls::{
    ec, pkey,
    ssl::{
        SslAcceptor, SslAlert, SslConnector, SslMethod, SslVerifyError, SslVerifyMode, SslVersion,
    },
};
use rp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    BoxConnection, BoxHostKey, BoxListener, BoxStream, Connection, Listener, PeerId, PublicKey,
    Transport,
};
use rp2p_mux::{Reason, YamuxConn, INIT_WINDOW_SIZE};

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
pub struct TcpTransport;

impl TcpTransport {
    /// Create new tcp transport with provided [`yamux::Config`]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Transport for TcpTransport {
    /// Test if this transport support the `laddr`.
    fn multiaddr_hint(&self, laddr: &Multiaddr) -> bool {
        let stack = laddr.protocol_stack().collect::<Vec<_>>();

        if stack.len() > 1 {
            if stack[1] == "tcp" {
                return true;
            }
        }

        return false;
    }
    /// Create a server side socket and bind it on `laddr`.
    async fn bind(&self, host_key: Arc<BoxHostKey>, laddr: &Multiaddr) -> io::Result<BoxListener> {
        let (cert, pk) = rp2p_x509::generate(&**host_key).await?;

        let cert = rasi_ext::net::tls::x509::X509::from_der(&cert)?;

        let pk = pkey::PKey::from_ec_key(ec::EcKey::private_key_from_der(&pk)?)?;

        let mut ssl_acceptor_builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

        ssl_acceptor_builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        ssl_acceptor_builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;

        ssl_acceptor_builder.set_certificate(&cert)?;

        ssl_acceptor_builder.set_private_key(&pk)?;

        ssl_acceptor_builder.check_private_key()?;

        ssl_acceptor_builder.set_custom_verify_callback(
            SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT,
            |ssl| {
                let cert = ssl
                    .peer_certificate()
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

        let ssl_acceptor = ssl_acceptor_builder.build();

        let addr =
            to_sockaddr(laddr).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid laddr"))?;

        let listener = TcpListener::bind(addr).await?;

        let laddr = listener.local_addr()?;

        Ok(Box::new(P2pTcpListener::new(ssl_acceptor, listener, laddr)))
    }

    /// Create a client socket and establish one [`Connection`](Connection) to `raddr`.
    async fn connect(
        &self,
        host_key: Arc<BoxHostKey>,
        raddr: &Multiaddr,
    ) -> io::Result<BoxConnection> {
        let (cert, pk) = rp2p_x509::generate(&**host_key).await?;

        let cert = rasi_ext::net::tls::x509::X509::from_der(&cert)?;

        let pk = pkey::PKey::from_ec_key(ec::EcKey::private_key_from_der(&pk)?)?;

        let mut config = SslConnector::builder(SslMethod::tls_client())?;

        config.set_certificate(&cert)?;

        config.set_private_key(&pk)?;

        config.set_max_proto_version(Some(SslVersion::TLS1_3))?;
        config.set_min_proto_version(Some(SslVersion::TLS1_3))?;

        config.set_custom_verify_callback(SslVerifyMode::PEER, |ssl| {
            let cert = ssl
                .peer_certificate()
                .ok_or(SslVerifyError::Invalid(SslAlert::CERTIFICATE_REQUIRED))?;

            let cert = cert
                .to_der()
                .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?;

            let peer_id = rp2p_x509::verify(cert)
                .map_err(|_| SslVerifyError::Invalid(SslAlert::BAD_CERTIFICATE))?
                .to_peer_id();

            log::trace!("ssl_client: verified peer={}", peer_id);

            Ok(())
        });

        let config = config.build().configure()?;

        let addr =
            to_sockaddr(raddr).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid laddr"))?;

        let mut stream = TcpStream::connect(addr).await?;

        let laddr = stream.local_addr()?;

        // dynamic select the secure protocol.
        let (_, _) = dialer_select_proto(&mut stream, ["/tls/1.0.0"], Version::V1).await?;

        let mut stream = rasi_ext::net::tls::connect(config, &addr.ip().to_string(), stream)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or(io::Error::new(io::ErrorKind::Other, "Handshaking"))?;

        let public_key = rp2p_x509::verify(cert.to_der()?)?;

        let (_, _) = dialer_select_proto(&mut stream, ["/yamux/1.0.0"], Version::V1).await?;

        let stream: BoxStream = Box::new(stream);

        Ok(Box::new(P2pTcpConn::new(
            laddr, addr, public_key, stream, false,
        )?))
    }
}

struct P2pTcpListener {
    laddr: SocketAddr,
    ssl_acceptor: SslAcceptor,
    listener: TcpListener,
}

impl P2pTcpListener {
    fn new(ssl_acceptor: SslAcceptor, listener: TcpListener, laddr: SocketAddr) -> Self {
        Self {
            laddr,
            ssl_acceptor,
            listener,
        }
    }
}

#[async_trait]
impl Listener for P2pTcpListener {
    async fn accept(&self) -> io::Result<BoxConnection> {
        let (mut stream, raddr) = self.listener.accept().await?;

        let (_, _) = listener_select_proto(&mut stream, ["/tls/1.0.0"]).await?;

        let mut stream = rasi_ext::net::tls::accept(&self.ssl_acceptor, stream)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        let cert = stream
            .ssl()
            .peer_certificate()
            .ok_or(io::Error::new(io::ErrorKind::Other, "Handshaking"))?;

        let public_key = rp2p_x509::verify(cert.to_der()?)?;

        let (_, _) = listener_select_proto(&mut stream, ["/yamux/1.0.0"]).await?;

        let stream: BoxStream = Box::new(stream);

        Ok(Box::new(P2pTcpConn::new(
            self.laddr, raddr, public_key, stream, true,
        )?))
    }

    fn local_addr(&self) -> io::Result<Multiaddr> {
        let mut addr = Multiaddr::from(self.laddr.ip());
        addr.push(Protocol::Tcp(self.laddr.port()));

        Ok(addr)
    }
}

struct P2pTcpConn {
    public_key: PublicKey,
    laddr: SocketAddr,
    raddr: SocketAddr,
    conn: YamuxConn,
}

impl P2pTcpConn {
    fn new(
        laddr: SocketAddr,
        raddr: SocketAddr,
        public_key: PublicKey,
        stream: BoxStream,
        is_server: bool,
    ) -> io::Result<Self> {
        let (read, write) = stream.split();
        let conn = rp2p_mux::YamuxConn::new_with(INIT_WINDOW_SIZE, is_server, read, write);

        Ok(Self {
            laddr,
            raddr,
            conn,
            public_key,
        })
    }
}

#[async_trait]
impl Connection for P2pTcpConn {
    /// Returns local bind address.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out which port was
    /// actually bound.
    fn local_addr(&self) -> io::Result<Multiaddr> {
        let mut addr = Multiaddr::from(self.laddr.ip());
        addr.push(Protocol::Tcp(self.laddr.port()));

        Ok(addr)
    }

    /// Returns the remote address that this connection is connected to.
    fn peer_addr(&self) -> io::Result<Multiaddr> {
        let mut addr = Multiaddr::from(self.raddr.ip());
        addr.push(Protocol::Tcp(self.raddr.port()));

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
        let stream = self.conn.stream_open().await?;

        Ok(Box::new(stream))
    }

    /// Accept newly incoming stream for reading/writing.
    ///
    /// If the connection is dropping or has been dropped, this function will returns `None`.
    async fn accept(&self) -> io::Result<BoxStream> {
        let stream = self.conn.stream_accept().await?;

        Ok(Box::new(stream))
    }

    async fn close(&self) -> io::Result<()> {
        self.conn.close(Reason::Normal).await?;

        Ok(())
    }
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
    use rp2p_core::{HostKey, Keypair};

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
        register_futures_executor();

        let transport = TcpTransport::default();

        let server_host_key: Arc<BoxHostKey> = Arc::new(Box::new(MockHostKey::default()));

        let laddr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();

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
