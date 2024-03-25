use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use rasi::net::{TcpListener, TcpStream};
use rasi_ext::net::tls::{
    ec, pkey,
    ssl::{SslAcceptor, SslConnector, SslMethod},
    SslStream,
};
use rp2p_core::{
    multiaddr::{Multiaddr, Protocol},
    BoxConnection, BoxHostKey, BoxListener, BoxStream, Connection, Listener, PeerId, PublicKey,
    Transport,
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
pub struct Tcp;

#[async_trait]
impl Transport for Tcp {
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

        let mut ssl_acceptor_builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;

        let cert = rasi_ext::net::tls::x509::X509::from_der(&cert)?;

        ssl_acceptor_builder.add_client_ca(&cert)?;

        let pk = pkey::PKey::from_ec_key(ec::EcKey::private_key_from_der(&pk)?)?;

        ssl_acceptor_builder.set_private_key(&pk)?;

        ssl_acceptor_builder.check_private_key()?;

        let ssl_acceptor = ssl_acceptor_builder.build();

        let addr =
            to_sockaddr(laddr).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid laddr"))?;

        let listener = TcpListener::bind(addr).await.unwrap();

        Ok(Box::new(P2pTcpListener::new(ssl_acceptor, listener, addr)))
    }

    /// Create a client socket and establish one [`Connection`](Connection) to `raddr`.
    async fn connect(
        &self,
        host_key: Arc<BoxHostKey>,
        raddr: &Multiaddr,
    ) -> io::Result<BoxConnection> {
        let (cert, pk) = rp2p_x509::generate(&**host_key).await?;

        let cert = rasi_ext::net::tls::x509::X509::from_der(&cert)?;

        let mut config = SslConnector::builder(SslMethod::tls()).unwrap();

        config.set_certificate(&cert)?;

        let pk = pkey::PKey::from_ec_key(ec::EcKey::private_key_from_der(&pk)?)?;

        config.set_private_key(&pk)?;

        let config = config.build().configure().unwrap();

        let addr =
            to_sockaddr(raddr).ok_or(io::Error::new(io::ErrorKind::Other, "Invalid laddr"))?;

        let stream = TcpStream::connect(addr).await?;

        let laddr = stream.local_addr()?;

        let stream = rasi_ext::net::tls::connect(config, &addr.ip().to_string(), stream)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        Ok(Box::new(P2pTcpConn::new(laddr, addr, stream)))
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
        let (conn, raddr) = self.listener.accept().await?;

        let stream = rasi_ext::net::tls::accept(&self.ssl_acceptor, conn)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err))?;

        Ok(Box::new(P2pTcpConn::new(self.laddr, raddr, stream)))
    }
}

struct P2pTcpConn {
    laddr: SocketAddr,
    raddr: SocketAddr,
    stream: SslStream<TcpStream>,
}

impl P2pTcpConn {
    fn new(laddr: SocketAddr, raddr: SocketAddr, stream: SslStream<TcpStream>) -> Self {
        Self {
            laddr,
            raddr,
            stream,
        }
    }
}

#[async_trait]
impl Connection for P2pTcpConn {
    /// Returns local bind address.
    ///
    /// This can be useful, for example, when binding to port 0 to figure out which port was
    /// actually bound.
    fn local_addr(&self) -> io::Result<Multiaddr> {
        todo!()
    }

    /// Returns the remote address that this connection is connected to.
    fn peer_addr(&self) -> io::Result<Multiaddr> {
        todo!()
    }

    /// Return peer's id obtained from secure layer peer's public key.
    fn peer_id(&self) -> io::Result<PeerId> {
        todo!()
    }

    /// Return the secure layer peer's public key.
    fn public_key(&self) -> io::Result<PublicKey> {
        todo!()
    }

    /// Open a outbound stream for reading/writing via this connection.
    async fn open(&self) -> io::Result<BoxStream> {
        todo!()
    }

    /// Accept newly incoming stream for reading/writing.
    ///
    /// If the connection is dropping or has been dropped, this function will returns `None`.
    async fn accept(&self) -> io::Result<BoxStream> {
        todo!()
    }
}
