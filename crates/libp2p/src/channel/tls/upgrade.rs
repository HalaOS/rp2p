use std::{
    io::{self, Cursor, Write},
    net::Shutdown,
    sync::Arc,
    task::{Context, Waker},
};

use identity::PeerId;
use multiaddr::Multiaddr;
use rasi::{
    poll_cancelable,
    syscall::{CancelablePoll, Handle, PendingHandle},
};
use rasi_ext::utils::{Lockable, LockableNew, SpinMutex};
use rustls::{
    pki_types::ServerName, ClientConfig, ClientConnection, ServerConfig, ServerConnection,
};
use verifier::{Libp2pCertificateVerifier, PROTOCOL_VERSIONS};

use crate::{
    errors::{P2pError, Result},
    ChannelIo, HandleContext, KeypairProvider, SecureUpgrade, Transport,
};

use super::{super::utils::to_sockaddr, cert::tls_cer_gen, verifier};

#[allow(unused)]
struct TlsBuffer {
    is_server: bool,
    handle: Arc<Handle>,
    transport: std::sync::Arc<Box<dyn Transport>>,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
    read_pending: Option<PendingHandle>,
    write_pending: Option<PendingHandle>,
}

impl TlsBuffer {
    pub fn new(
        is_server: bool,
        handle: Arc<Handle>,
        transport: std::sync::Arc<Box<dyn Transport>>,
    ) -> Self {
        Self {
            is_server,
            handle,
            transport,
            read_waker: None,
            write_waker: None,
            read_pending: None,
            write_pending: None,
        }
    }
    pub fn register_read(&mut self, waker: Waker) {
        self.read_waker = Some(waker);
    }

    pub fn register_write(&mut self, waker: Waker) {
        self.write_waker = Some(waker);
    }

    pub fn is_read_pending(&self) -> bool {
        self.read_waker.is_some()
    }

    pub fn is_write_pending(&self) -> bool {
        self.write_waker.is_some()
    }
}

#[allow(unused)]
impl io::Write for TlsBuffer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let waker = self.write_waker.take().unwrap();

        match self.transport.write(
            &mut Context::from_waker(&waker),
            &self.handle,
            buf,
            self.write_pending.take(),
        ) {
            CancelablePoll::Ready(r) => {
                log::trace!("TlsBuffer, write: {:?}", r);
                r
            }
            CancelablePoll::Pending(write_pending) => {
                log::trace!("TlsBuffer, write: pending");
                self.write_pending = write_pending;

                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Transport write pending",
                ))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[allow(unused)]
impl io::Read for TlsBuffer {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read_waker = self.read_waker.take().unwrap();
        match self.transport.read(
            &mut Context::from_waker(&read_waker),
            &self.handle,
            buf,
            self.read_pending.take(),
        ) {
            CancelablePoll::Ready(r) => {
                self.read_waker = Some(read_waker);
                log::trace!("TlsBuffer, read: {:?}", r);
                return r;
            }
            CancelablePoll::Pending(read_pending) => {
                log::trace!("TlsBuffer, read: pending");
                self.read_pending = read_pending;

                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "Transport read pending",
                ));
            }
        }
    }
}

struct TlsStream {
    handle: Arc<Handle>,
    transport: std::sync::Arc<Box<dyn Transport>>,
    tls_conn: SpinMutex<(rustls::Connection, TlsBuffer)>,
}

impl TlsStream {
    pub fn new(
        handle: Arc<Handle>,
        transport: Arc<Box<dyn Transport>>,
        tls_conn: rustls::Connection,
        is_server: bool,
    ) -> Self {
        Self {
            handle,
            transport,
            tls_conn: SpinMutex::new((tls_conn, TlsBuffer::new(is_server, handle, transport))),
        }
    }

    pub fn write(&self, cx: &mut Context<'_>, buf: &[u8]) -> CancelablePoll<io::Result<usize>> {
        let mut tls_conn = self.tls_conn.lock();

        let write_size = match tls_conn.0.writer().write(buf) {
            Ok(write_size) => write_size,
            Err(err) => return CancelablePoll::Ready(Err(err)),
        };

        todo!()
    }

    pub fn read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> CancelablePoll<io::Result<usize>> {
        let mut tls_conn = self.tls_conn.lock();

        todo!()
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let mut tls_conn = self.tls_conn.lock();

        todo!()
    }

    pub fn handshake(&self, cx: &mut Context<'_>) -> CancelablePoll<io::Result<()>> {
        let mut tls_conn = self.tls_conn.lock();

        todo!()
    }
}

#[derive(Default)]
pub struct TlsSecureUpgrade;

impl ChannelIo for TlsSecureUpgrade {
    fn write(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &Handle,
        buf: &[u8],
        _pending: Option<rasi::syscall::PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>> {
        if buf.len() == 0 {
            return CancelablePoll::Ready(Ok(0));
        }

        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.write(cx, buf)
    }

    fn read(
        &self,
        cx: &mut std::task::Context<'_>,
        handle: &Handle,
        buf: &mut [u8],
        _pending: Option<rasi::syscall::PendingHandle>,
    ) -> CancelablePoll<io::Result<usize>> {
        if buf.len() == 0 {
            return CancelablePoll::Ready(Ok(0));
        }

        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.read(cx, buf)
    }

    fn shutdown(&self, handle: &Handle, how: std::net::Shutdown) -> io::Result<()> {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.shutdown(how)
    }
}

impl HandleContext for TlsSecureUpgrade {
    fn fmt(&self, handle: &Handle, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.transport.fmt(&stream.handle, f)
    }

    fn peer_addr(&self, handle: &Handle) -> Multiaddr {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.transport.peer_addr(&stream.handle)
    }

    fn public_key<'a>(&self, _handle: &'a Handle) -> Option<&'a identity::PublicKey> {
        todo!()
    }

    fn is_server(&self, handle: &Handle) -> bool {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.transport.is_server(&stream.handle)
    }

    fn local_addr(&self, handle: &Handle) -> Multiaddr {
        let stream = handle.downcast::<TlsStream>().expect("Expect TlsStream");

        stream.transport.local_addr(&stream.handle)
    }
}

impl SecureUpgrade for TlsSecureUpgrade {
    fn handshake(
        &self,
        cx: &mut std::task::Context<'_>,
        upgrade_handle: &Handle,
        _pending: Option<rasi::syscall::PendingHandle>,
    ) -> CancelablePoll<io::Result<()>> {
        let stream = upgrade_handle
            .downcast::<TlsStream>()
            .expect("Expect TlsStream");

        stream.handshake(cx)
    }

    fn upgrade_client(
        &self,
        cx: &mut Context<'_>,
        handle: Arc<Handle>,
        transport: Arc<Box<dyn Transport>>,
        keypair: Arc<Box<dyn KeypairProvider>>,
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<Handle>> {
        let poll = poll_cancelable!(UpgradeClient, cx, pending, || async {
            make_client_config(&**keypair, None).await
        });

        let config = match poll {
            CancelablePoll::Ready(config) => match config {
                Ok(config) => config,
                Err(err) => return CancelablePoll::Ready(Err(err.into())),
            },
            CancelablePoll::Pending(r) => return CancelablePoll::Pending(r),
        };

        let addr = match to_sockaddr(&transport.peer_addr(&handle)) {
            Some(addr) => addr,
            None => {
                return CancelablePoll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TlsUpgrade: peer_addr is not a valid tcp/udp address.",
                )));
            }
        };

        let tls_conn = match ClientConnection::new(
            Arc::new(config),
            ServerName::IpAddress(addr.ip().into()),
        ) {
            Ok(conn) => conn,
            Err(err) => return CancelablePoll::Ready(Err(P2pError::RustlsError(err).into())),
        };

        CancelablePoll::Ready(Ok(Handle::new(TlsStream::new(
            handle,
            transport,
            tls_conn.into(),
        ))))
    }

    fn upgrade_server(
        &self,
        cx: &mut Context<'_>,
        handle: Arc<Handle>,
        transport: Arc<Box<dyn Transport>>,
        keypair: Arc<Box<dyn KeypairProvider>>,
        pending: Option<PendingHandle>,
    ) -> CancelablePoll<io::Result<Handle>> {
        let poll = poll_cancelable!(UpgradeClient, cx, pending, || async {
            make_server_config(&**keypair).await
        });

        let config = match poll {
            CancelablePoll::Ready(config) => match config {
                Ok(config) => config,
                Err(err) => return CancelablePoll::Ready(Err(err.into())),
            },
            CancelablePoll::Pending(r) => return CancelablePoll::Pending(r),
        };

        let tls_conn = match ServerConnection::new(Arc::new(config)) {
            Ok(conn) => conn,
            Err(err) => return CancelablePoll::Ready(Err(P2pError::RustlsError(err).into())),
        };

        CancelablePoll::Ready(Ok(Handle::new(TlsStream::new(
            handle,
            transport,
            tls_conn.into(),
        ))))
    }
}

const P2P_ALPN: [u8; 6] = *b"libp2p";

/// Create a TLS client configuration for libp2p.
pub async fn make_client_config(
    keypair: &dyn KeypairProvider,
    remote_peer_id: Option<PeerId>,
) -> Result<rustls::ClientConfig> {
    let (certificate, private_key) = tls_cer_gen(keypair).await?;

    let mut config = ClientConfig::builder_with_protocol_versions(PROTOCOL_VERSIONS)
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Libp2pCertificateVerifier::with_remote_peer_id(
            remote_peer_id,
        )))
        .with_client_auth_cert(vec![certificate], private_key)?;

    config.alpn_protocols = vec![P2P_ALPN.to_vec()];

    Ok(config)
}

pub async fn make_server_config(keypair: &dyn KeypairProvider) -> Result<rustls::ServerConfig> {
    let (certificate, private_key) = tls_cer_gen(keypair).await?;

    let mut config = ServerConfig::builder_with_protocol_versions(PROTOCOL_VERSIONS)
        .with_client_cert_verifier(Arc::new(Libp2pCertificateVerifier::new()))
        .with_single_cert(vec![certificate], private_key)?;

    config.alpn_protocols = vec![P2P_ALPN.to_vec()];

    Ok(config)
}
