use std::{
    io::{self, Read, Write},
    net::Shutdown,
    sync::Arc,
    task::{Context, Waker},
};

use boring::{
    conf,
    ssl::{MidHandshakeSslStream, SslAcceptor, SslConnector, SslMethod, SslStream},
};
use identity::PeerId;
use multiaddr::Multiaddr;
use rasi::syscall::{CancelablePoll, Handle, PendingHandle};
use rasi_ext::utils::{Lockable, LockableNew, SpinMutex};
use rustls::{ClientConfig, ServerConfig};
use verifier::{Libp2pCertificateVerifier, PROTOCOL_VERSIONS};

use crate::{
    errors::{P2pError, Result},
    ChannelIo, HandleContext, KeypairProvider, SecureUpgrade, Transport,
};

use super::{
    super::utils::to_sockaddr,
    cert::{self, tls_cer_gen},
    verifier,
};

#[derive(Default)]
pub struct TlsSecureUpgrade;

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
enum TlsState {
    Handshake(Option<MidHandshakeSslStream<TlsBuffer>>),
    Stream(SslStream<TlsBuffer>),
}

struct TlsStream {
    handle: Arc<Handle>,
    transport: std::sync::Arc<Box<dyn Transport>>,
    state: SpinMutex<TlsState>,
}

impl TlsStream {
    pub fn new(
        handle: Arc<Handle>,
        transport: Arc<Box<dyn Transport>>,
        handshake: MidHandshakeSslStream<TlsBuffer>,
    ) -> Self {
        Self {
            handle,
            transport,
            state: SpinMutex::new(TlsState::Handshake(Some(handshake))),
        }
    }

    pub fn write(&self, cx: &mut Context<'_>, buf: &[u8]) -> CancelablePoll<io::Result<usize>> {
        let mut state = self.state.lock();

        match &mut *state {
            TlsState::Stream(stream) => {
                stream.get_mut().register_write(cx.waker().clone());
                match stream.write(buf) {
                    Ok(write_size) => {
                        if write_size == 0 && stream.get_mut().is_write_pending() {
                            return CancelablePoll::Pending(None);
                        }

                        return CancelablePoll::Ready(Ok(write_size));
                    }
                    Err(err) => {
                        return CancelablePoll::Ready(Err(err));
                    }
                }
            }
            TlsState::Handshake(_) => CancelablePoll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "Call handshake first",
            ))),
        }
    }

    pub fn read(&self, cx: &mut Context<'_>, buf: &mut [u8]) -> CancelablePoll<io::Result<usize>> {
        let mut state = self.state.lock();

        match &mut *state {
            TlsState::Stream(stream) => {
                stream.get_mut().register_read(cx.waker().clone());
                match stream.read(buf) {
                    Ok(write_size) => {
                        if write_size == 0 && stream.get_mut().is_read_pending() {
                            return CancelablePoll::Pending(None);
                        }

                        return CancelablePoll::Ready(Ok(write_size));
                    }
                    Err(err) => {
                        return CancelablePoll::Ready(Err(err));
                    }
                }
            }
            TlsState::Handshake(_) => CancelablePoll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "Call handshake first",
            ))),
        }
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        let mut state = self.state.lock();

        match &mut *state {
            TlsState::Stream(_) => self.transport.shutdown(&self.handle, how),
            TlsState::Handshake(_) => {
                Err(io::Error::new(io::ErrorKind::Other, "Call handshake first"))
            }
        }
    }

    pub fn handshake(&self, cx: &mut Context<'_>) -> CancelablePoll<io::Result<()>> {
        let mut state = self.state.lock();
        match &mut *state {
            TlsState::Stream(_) => CancelablePoll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                "Already handshake successfully",
            ))),
            TlsState::Handshake(handshake) => {
                let mut handshake = handshake.take().unwrap();
                handshake.get_mut().register_read(cx.waker().clone());
                handshake.get_mut().register_write(cx.waker().clone());
                handshake.ssl_mut().set_task_waker(Some(cx.waker().clone()));

                log::trace!(
                    "server({}), handshake",
                    self.transport.is_server(&self.handle)
                );

                match handshake.handshake() {
                    Ok(stream) => {
                        log::trace!("handshake ok");
                        *state = TlsState::Stream(stream);

                        return CancelablePoll::Ready(Ok(()));
                    }
                    Err(boring::ssl::HandshakeError::WouldBlock(handshake)) => {
                        log::trace!(
                            "server({}), handshake pending...",
                            self.transport.is_server(&self.handle)
                        );
                        *state = TlsState::Handshake(Some(handshake));
                        return CancelablePoll::Pending(None);
                    }
                    Err(boring::ssl::HandshakeError::Failure(_)) => {
                        return CancelablePoll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "handshake failed",
                        )))
                    }
                    Err(boring::ssl::HandshakeError::SetupFailure(err_stack)) => {
                        return CancelablePoll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            err_stack,
                        )))
                    }
                }
            }
        }
    }
}

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
    fn upgrade_client(
        &self,
        handle: Handle,
        transport: std::sync::Arc<Box<dyn Transport>>,
        _keypair: std::sync::Arc<Box<dyn crate::KeypairProvider>>,
    ) -> io::Result<Handle> {
        let config = SslConnector::builder(SslMethod::tls()).unwrap();

        let config = config.build().configure().unwrap();

        let handle = Arc::new(handle);

        let addr = match to_sockaddr(&transport.peer_addr(&handle)) {
            Some(addr) => addr,
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TlsUpgrade: peer_addr is not a valid tcp/udp address.",
                ));
            }
        };

        let handshake = config
            .setup_connect(
                &addr.ip().to_string(),
                TlsBuffer::new(false, handle.clone(), transport.clone()),
            )
            .map_err(|err| P2pError::BoringErrStack(err))?;

        Ok(Handle::new(TlsStream::new(handle, transport, handshake)))
    }

    fn upgrade_server(
        &self,
        handle: Handle,
        transport: std::sync::Arc<Box<dyn Transport>>,
        _keypair: std::sync::Arc<Box<dyn crate::KeypairProvider>>,
    ) -> io::Result<Handle> {
        let builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();

        let ssl_acceptor = builder.build();

        let handle = Arc::new(handle);

        let handshake = ssl_acceptor
            .setup_accept(TlsBuffer::new(true, handle.clone(), transport.clone()))
            .map_err(|err| P2pError::BoringErrStack(err))?;

        Ok(Handle::new(TlsStream::new(handle, transport, handshake)))
    }

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
